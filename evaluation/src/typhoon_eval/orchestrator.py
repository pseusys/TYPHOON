"""
TYPHOON evaluation orchestrator.

Runs a Docker Compose capture session for each selected protocol, waits for
the client container to finish transferring data, then tears down.  The
observer container writes a pcap to results/captures/<protocol>[_chaos].pcap.

Usage (via poe):
    poe capture --all
    poe capture --all --chaos
    poe capture --protocol typhoon
    poe capture --protocol wireguard --chaos --timeout 600

Usage (direct):
    python -m typhoon_eval.orchestrator --all [--chaos] [--timeout 300] [--bytes 104857600]
"""

import datetime
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .docker_utils import COMPOSE_DIR, compose_up
from .protocols import ALL, BY_NAME, Protocol

console = Console()

RESULTS_DIR = Path(__file__).parent.parent.parent / "results"
ENV_DIR = COMPOSE_DIR / "env"


def _run_one(
    protocol: Protocol,
    chaos: bool,
    timeout: int,
    chaos_multiplier: int,
    transfer_bytes: int,
    captures_dir: Path,
) -> tuple[bool, str, float | None]:
    """
    Run a single protocol capture.
    Returns (success, error_message).
    """
    env_file = ENV_DIR / f".env.{protocol.name}"
    if not env_file.exists():
        return False, f"missing env file: {env_file}"

    suffix = "_chaos" if chaos else ""
    pumba_target = f"re2:typhoon-eval-{protocol.name.replace('_', '-')}-client-1"

    # Allow per-protocol TIMEOUT override in the env file.
    effective_timeout = timeout
    for line in env_file.read_text().splitlines():
        key, _, val = line.strip().partition("=")
        if not key or key.startswith("#"):
            continue
        elif key == "TIMEOUT":
            effective_timeout = int(val)
    if chaos:
        effective_timeout *= chaos_multiplier

    extra_env = {
        "PROTOCOL": protocol.name,
        "PROTOCOL_SUFFIX": suffix,
        "CLIENT_IMAGE": protocol.client_image,
        "SERVER_IMAGE": protocol.server_image,
        "TRANSFER_BYTES": str(transfer_bytes),
        "CAPTURES_DIR": str(captures_dir.resolve()),
        "PUMBA_TARGET": pumba_target,
    }

    success, delivery_pct = compose_up(
        protocol_name=protocol.name,
        env_file=env_file,
        extra_env=extra_env,
        chaos=chaos,
        timeout=effective_timeout,
    )

    pcap = captures_dir / f"{protocol.name}{suffix}.pcap"
    if success:
        if not pcap.exists():
            return False, "observer did not write pcap", None
        if pcap.stat().st_size < 100:
            return False, f"pcap is empty ({pcap.stat().st_size} bytes)", None

    return success, "" if success else "non-zero exit or timeout", delivery_pct


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--all", "run_all", is_flag=True, help="Capture all protocols.")
@click.option(
    "--protocol",
    "protocol_name",
    default=None,
    metavar="NAME",
    help=f"Capture one protocol. Choices: {', '.join(BY_NAME)}.",
)
@click.option("--chaos", is_flag=True, default=False, help="Enable pumba chaos overlay (latency + jitter).")
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Per-protocol timeout in seconds before the run is killed.",
)
@click.option(
    "--chaos-multiplier",
    "chaos_multiplier",
    default=3,
    show_default=True,
    help="Multiply per-protocol timeout by this factor when --chaos is active.",
)
@click.option(
    "--bytes",
    "transfer_bytes",
    default=None,
    type=int,
    help="Payload bytes transferred by each client (default 10 MB with --chaos, 100 MB otherwise).",
)
def main(run_all: bool, protocol_name: str | None, chaos: bool, timeout: int, chaos_multiplier: int, transfer_bytes: int | None) -> None:
    """TYPHOON evaluation — run traffic captures for protocol comparison."""

    if transfer_bytes is None:
        transfer_bytes = 10_485_760 if chaos else 104_857_600

    if not run_all and not protocol_name:
        console.print("[red]Error:[/red] specify --all or --protocol <name>.")
        console.print(f"Available protocols: {', '.join(BY_NAME)}")
        sys.exit(1)

    if protocol_name and protocol_name not in BY_NAME:
        console.print(f"[red]Unknown protocol:[/red] {protocol_name!r}")
        console.print(f"Available: {', '.join(BY_NAME)}")
        sys.exit(1)

    protocols = list(ALL) if run_all else [BY_NAME[protocol_name]]
    chaos_note = " [yellow](chaos mode)[/yellow]" if chaos else ""

    timeout_note = f"{timeout}s per run (env file may override per protocol)"
    if chaos:
        timeout_note += f", ×{chaos_multiplier} in chaos mode"

    console.print(f"\n[bold]TYPHOON evaluation{chaos_note}[/bold]")
    console.print(f"  Protocols : {', '.join(p.name for p in protocols)}")
    console.print(f"  Timeout   : {timeout_note}")
    console.print(f"  Transfer  : {transfer_bytes / 1_048_576:.0f} MB\n")

    captures_dir = RESULTS_DIR / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "logs").mkdir(parents=True, exist_ok=True)

    run_results: dict[str, dict] = {}

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            for protocol in protocols:
                task = progress.add_task(
                    f"  [cyan]{protocol.name:<16}[/cyan] {protocol.description}",
                    total=None,
                )
                started_at = datetime.datetime.now(datetime.UTC)

                success, error, delivery_pct = _run_one(
                    protocol=protocol,
                    chaos=chaos,
                    timeout=timeout,
                    chaos_multiplier=chaos_multiplier,
                    transfer_bytes=transfer_bytes,
                    captures_dir=captures_dir,
                )

                elapsed = (datetime.datetime.now(datetime.UTC) - started_at).total_seconds()
                run_results[protocol.name] = {
                    "success": success,
                    "error": error,
                    "elapsed_s": round(elapsed, 1),
                    "chaos": chaos,
                    "transfer_bytes": transfer_bytes,
                    "delivery_pct": delivery_pct,
                    "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                }

                icon = "[green]✓[/green]" if success else "[red]✗[/red]"
                detail = "" if success else f" [dim]— {error}[/dim]"
                progress.update(
                    task,
                    description=f"  {icon} [cyan]{protocol.name:<16}[/cyan] {protocol.description}{detail}",
                    total=1,
                    completed=1,
                )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — containers cleaned up.[/yellow]")
        sys.exit(1)

    # Summary table
    table = Table(title="Capture summary", show_lines=True)
    table.add_column("Protocol", style="cyan", no_wrap=True)
    table.add_column("Transport", style="dim")
    table.add_column("Status")
    table.add_column("Delivery", justify="right")
    table.add_column("Time (s)", justify="right", style="dim")

    ok = 0
    for p in protocols:
        r = run_results[p.name]
        status = "[green]OK[/green]" if r["success"] else "[red]FAIL[/red]"
        pct = r.get("delivery_pct")
        if pct is None:
            delivery = "[dim]—[/dim]"
        elif pct >= 99.9:
            delivery = f"[green]{pct:.1f}%[/green]"
        elif pct >= 80.0:
            delivery = f"[yellow]{pct:.1f}%[/yellow]"
        else:
            delivery = f"[red]{pct:.1f}%[/red]"
        table.add_row(p.name, p.transport, status, delivery, str(r["elapsed_s"]))
        if r["success"]:
            ok += 1

    console.print(table)
    console.print(f"\n{ok}/{len(protocols)} captures succeeded.\n")

    # Persist metadata (merge with any prior runs)
    meta_path = RESULTS_DIR / "metadata.json"
    existing = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    existing.update(run_results)
    meta_path.write_text(json.dumps(existing, indent=2))
    console.print(f"Metadata → [dim]{meta_path}[/dim]\n")

    sys.exit(0 if ok == len(protocols) else 1)


if __name__ == "__main__":
    main()
