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
    python -m typhoon_eval.orchestrator --all [--chaos] [--timeout 300] [--bytes 10485760] [--delay-ms 40] [--delay-every 10]
"""

import datetime
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .docker_utils import COMPOSE_DIR, _purge_stale_stacks, compose_up
from .protocols import ALL, BY_NAME, Protocol

console = Console()

RESULTS_DIR = Path(__file__).parent.parent.parent / "results"
ENV_DIR = COMPOSE_DIR / "env"


def _run_one(
    protocol: Protocol,
    chaos: bool,
    timeout: int,
    transfer_bytes: int,
    delay_ms: float,
    delay_every: int,
    captures_dir: Path,
    log_dir: Path,
) -> tuple[bool, str, float | None]:
    """
    Run a single protocol capture.
    Returns (success, error_message, delivery_pct).
    """
    env_file = ENV_DIR / f".env.{protocol.name}"
    if not env_file.exists():
        return False, f"missing env file: {env_file}", None

    suffix = "_chaos" if chaos else ""
    pumba_target = f"re2:typhoon-eval-{protocol.name.replace('_', '-')}-client-1"

    effective_timeout = timeout
    for line in env_file.read_text().splitlines():
        key, _, val = line.strip().partition("=")
        if not key or key.startswith("#"):
            continue
        elif key == "TIMEOUT":
            effective_timeout = int(val)

    extra_env = {
        "PROTOCOL": protocol.name,
        "PROTOCOL_SUFFIX": suffix,
        "CLIENT_IMAGE": protocol.client_image,
        "SERVER_IMAGE": protocol.server_image,
        "TRANSFER_BYTES": str(transfer_bytes),
        "CAPTURES_DIR": str(captures_dir.resolve()),
        "PUMBA_TARGET": pumba_target,
        "INTER_PACKET_DELAY_MS": str(delay_ms),
        "DELAY_EVERY_N": str(delay_every),
    }

    success, delivery_pct = compose_up(
        protocol_name=protocol.name,
        env_file=env_file,
        extra_env=extra_env,
        chaos=chaos,
        timeout=effective_timeout,
        log_dir=log_dir,
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
    "--bytes",
    "transfer_bytes",
    default=10_485_760,
    show_default=True,
    type=int,
    help="Payload bytes transferred by each client.",
)
@click.option(
    "--delay-ms",
    "delay_ms",
    default=40.0,
    show_default=True,
    type=float,
    help="Inter-packet sleep injected every --delay-every packets (ms). 0 = no delay.",
)
@click.option(
    "--delay-every",
    "delay_every",
    default=10,
    show_default=True,
    type=int,
    help="Apply inter-packet delay after every N packets.",
)
def main(run_all: bool, protocol_name: str | None, chaos: bool, timeout: int, transfer_bytes: int, delay_ms: float, delay_every: int) -> None:
    """TYPHOON evaluation — run traffic captures for protocol comparison."""

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

    # injected_delay_s is deterministic and identical for all senders with the same params
    chunk_size = 500
    n_sleep_points = (transfer_bytes // chunk_size) // delay_every
    injected_delay_s = n_sleep_points * delay_ms / 1000 if delay_ms > 0 else 0.0

    console.print(f"\n[bold]TYPHOON evaluation{chaos_note}[/bold]")
    console.print(f"  Protocols : {', '.join(p.name for p in protocols)}")
    console.print(f"  Timeout   : {timeout}s per run (env file may override per protocol)")
    console.print(f"  Transfer  : {transfer_bytes / 1_048_576:.0f} MB")
    if delay_ms > 0:
        console.print(f"  Delay     : {delay_ms}ms every {delay_every} packets → {injected_delay_s:.1f}s injected\n")
    else:
        console.print()

    run_id = "run_" + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    captures_dir = RESULTS_DIR / "captures" / run_id
    captures_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"  Run ID    : [dim]{run_id}[/dim]\n")

    config: dict = {
        "run_id": run_id,
        "started_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "protocols": [p.name for p in protocols],
        "chaos": chaos,
        "timeout_s": timeout,
        "transfer_bytes": transfer_bytes,
        "delay_ms": delay_ms,
        "delay_every": delay_every,
        "injected_delay_s": injected_delay_s,
    }
    (captures_dir / "config.json").write_text(json.dumps(config, indent=2))

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
                    transfer_bytes=transfer_bytes,
                    delay_ms=delay_ms,
                    delay_every=delay_every,
                    captures_dir=captures_dir,
                    log_dir=captures_dir / "logs" / protocol.name,
                )

                elapsed = (datetime.datetime.now(datetime.UTC) - started_at).total_seconds()
                effective_time_s = round(elapsed - injected_delay_s, 1) if injected_delay_s > 0 else None
                run_results[protocol.name] = {
                    "success": success,
                    "error": error,
                    "elapsed_s": round(elapsed, 1),
                    "effective_time_s": effective_time_s,
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
        _purge_stale_stacks()
        console.print("\n[yellow]Interrupted — containers cleaned up.[/yellow]")
        sys.exit(1)

    _purge_stale_stacks()

    # Summary table
    show_eff = injected_delay_s > 0
    table = Table(title="Capture summary", show_lines=True)
    table.add_column("Protocol", style="cyan", no_wrap=True)
    table.add_column("Transport", style="dim")
    table.add_column("Status")
    table.add_column("Delivery", justify="right")
    table.add_column("Elapsed (s)", justify="right", style="dim")
    if show_eff:
        table.add_column("Eff.Time (s)", justify="right")

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
        row = [p.name, p.transport, status, delivery, str(r["elapsed_s"])]
        if show_eff:
            eff = r.get("effective_time_s")
            row.append(str(eff) if eff is not None else "[dim]—[/dim]")
        table.add_row(*row)
        if r["success"]:
            ok += 1

    console.print(table)
    console.print(f"\n{ok}/{len(protocols)} captures succeeded.\n")

    meta_path = captures_dir / "metadata.json"
    meta_path.write_text(json.dumps(run_results, indent=2))
    console.print(f"Metadata → [dim]{meta_path}[/dim]\n")

    sys.exit(0 if ok == len(protocols) else 1)


if __name__ == "__main__":
    main()
