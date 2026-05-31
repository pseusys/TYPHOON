"""
TYPHOON evaluation orchestrator.

Runs a Docker Compose capture session for each selected protocol, waits for
the client container to finish transferring data, then tears down.  The
observer container writes a pcap to results/captures/<protocol>[_chaos].pcap.

Per-run profile parameters (chunk sizes, IATs, byte budgets, FlowConfig
overrides) are sampled from `shared/profiles.py` and passed to client and
server containers as `TRAFFIC_PROFILE` + `PROFILE_*` env vars.

Usage (via poe):
    poe capture --all
    poe capture --all --chaos
    poe capture --protocol typhoon
    poe capture --protocol wireguard --chaos --timeout 600

Usage (direct):
    python -m typhoon_eval.shared.orchestrator --all [--chaos] [--timeout 300] [--profile bulk_upload]
"""

from datetime import UTC, datetime
from json import dumps
from pathlib import Path
from random import Random
from sys import exit

from click import Choice, command, option
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .docker_utils import COMPOSE_DIR, _purge_stale_stacks, compose_up
from .profiles import DEFAULT_PROFILE, PROFILES, profile_to_env
from .protocols import ALL, BY_NAME, Protocol

console = Console()

RESULTS_DIR = Path(__file__).parent.parent.parent.parent / "results"

# Minimum pcap size to consider non-empty / capture-worthy (bytes).  Below this
# the file is essentially just the libpcap global header (24 B) plus a stub.
MIN_PCAP_SIZE_B = 100
# Delivery-rate colour bands — mirrors `shared/analysis.py`.
DELIVERY_GREEN_PCT = 99.9
DELIVERY_YELLOW_PCT = 80.0
ENV_DIR = COMPOSE_DIR / "env"


def _run_one(
    protocol: Protocol,
    chaos: bool,
    timeout: int,
    profile_env: dict[str, str],
    loss_pct: float,
    bw_mbps: float,
    captures_dir: Path,
    log_dir: Path,
) -> tuple[bool, str, float | None, float | None, float | None]:
    """
    Run a single protocol capture.
    Returns (success, error_message, delivery_pct, transfer_time_s, recv_time_s).
    """
    env_file = ENV_DIR / f".env.{protocol.name}"
    if not env_file.exists():
        return False, f"missing env file: {env_file}", None, None, None

    suffix = "_chaos" if chaos else ""
    pumba_target = f"re2:typhoon-eval-{protocol.name.replace('_', '-')}-client-1"

    effective_timeout = timeout
    for line in env_file.read_text().splitlines():
        key, _, val = line.strip().partition("=")
        if not key or key.startswith("#"):
            continue
        elif key == "TIMEOUT":
            effective_timeout = int(val)

    extra_env: dict[str, str] = {
        "PROTOCOL": protocol.name,
        "PROTOCOL_SUFFIX": suffix,
        "CLIENT_IMAGE": protocol.client_image,
        "SERVER_IMAGE": protocol.server_image,
        "CAPTURES_DIR": str(captures_dir.resolve()),
        "PUMBA_TARGET": pumba_target,
        "CHAOS_LOSS_PCT": str(loss_pct),
        "CHAOS_BW_MBPS": str(bw_mbps),
    }
    extra_env.update(profile_env)

    success, delivery_pct, transfer_time_s, recv_time_s = compose_up(
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
            return False, "observer did not write pcap", None, None, None
        if pcap.stat().st_size < MIN_PCAP_SIZE_B:
            return False, f"pcap is empty ({pcap.stat().st_size} bytes)", None, None, None

    return success, "" if success else "non-zero exit or timeout", delivery_pct, transfer_time_s, recv_time_s


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--all", "run_all", is_flag=True, help="Capture all protocols.")
@option(
    "--protocol",
    "protocol_name",
    default=None,
    metavar="NAME",
    help=f"Capture one protocol. Choices: {', '.join(BY_NAME)}.",
)
@option("--chaos", is_flag=True, default=False, help="Enable pumba chaos overlay (latency + jitter).")
@option(
    "--timeout",
    default=300,
    show_default=True,
    help="Per-protocol timeout in seconds before the run is killed.",
)
@option(
    "--profile",
    default=DEFAULT_PROFILE,
    show_default=True,
    type=Choice(list(PROFILES.keys())),
    help="Traffic profile (chunk sizes, IATs, byte budgets, FlowConfig overrides).",
)
@option(
    "--seed",
    default=None,
    type=int,
    help="RNG seed for sampling profile parameters (default: random).",
)
@option(
    "--loss-pct",
    "loss_pct",
    default=0.0,
    show_default=True,
    type=float,
    help="Chaos: packet loss percentage (0 = no extra loss beyond chaos default).",
)
@option(
    "--bw-mbps",
    "bw_mbps",
    default=0.0,
    show_default=True,
    type=float,
    help="Chaos: bandwidth cap in Mbps via tbf (0 = unlimited).",
)
def main(run_all: bool, protocol_name: str | None, chaos: bool, timeout: int, profile: str, seed: int | None, loss_pct: float, bw_mbps: float) -> None:
    """TYPHOON evaluation — run traffic captures for protocol comparison."""

    if not run_all and not protocol_name:
        console.print("[red]Error:[/red] specify --all or --protocol <name>.")
        console.print(f"Available protocols: {', '.join(BY_NAME)}")
        exit(1)

    if protocol_name and protocol_name not in BY_NAME:
        console.print(f"[red]Unknown protocol:[/red] {protocol_name!r}")
        console.print(f"Available: {', '.join(BY_NAME)}")
        exit(1)

    protocols = list(ALL) if run_all else [BY_NAME[protocol_name]]
    chaos_note = " [yellow](chaos mode)[/yellow]" if chaos else ""

    rng = Random(seed)
    profile_obj = PROFILES[profile]
    profile_env = profile_to_env(profile_obj, rng)
    transfer_bytes = int(profile_env["PROFILE_BYTES_C2S"])

    console.print(f"\n[bold]TYPHOON evaluation{chaos_note}[/bold]")
    console.print(f"  Protocols : {', '.join(p.name for p in protocols)}")
    console.print(f"  Timeout   : {timeout}s per run (env file may override per protocol)")
    console.print(f"  Profile   : {profile}  ({profile_obj.description})")
    console.print(f"  Transfer  : c2s={int(profile_env['PROFILE_BYTES_C2S']) / 1_048_576:.1f} MB / s2c={int(profile_env['PROFILE_BYTES_S2C']) / 1_048_576:.1f} MB")
    if chaos and (loss_pct > 0 or bw_mbps > 0):
        console.print(f"  Chaos     : loss={loss_pct}%  bw={bw_mbps or 'unlimited'} Mbps")
    console.print()

    run_id = "run_" + datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    captures_dir = RESULTS_DIR / "captures" / run_id
    captures_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"  Run ID    : [dim]{run_id}[/dim]\n")

    config: dict = {
        "run_id": run_id,
        "started_at": datetime.now(UTC).isoformat(),
        "protocols": [p.name for p in protocols],
        "chaos": chaos,
        "timeout_s": timeout,
        "profile": profile,
        "profile_env": profile_env,
        "transfer_bytes": transfer_bytes,
        "loss_pct": loss_pct,
        "bw_mbps": bw_mbps,
    }
    (captures_dir / "config.json").write_text(dumps(config, indent=2))

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
                started_at = datetime.now(UTC)

                success, error, delivery_pct, transfer_time_s, recv_time_s = _run_one(
                    protocol=protocol,
                    chaos=chaos,
                    timeout=timeout,
                    profile_env=profile_env,
                    loss_pct=loss_pct,
                    bw_mbps=bw_mbps,
                    captures_dir=captures_dir,
                    log_dir=captures_dir / "logs" / protocol.name,
                )

                elapsed = (datetime.now(UTC) - started_at).total_seconds()
                run_results[protocol.name] = {
                    "success": success,
                    "error": error,
                    "elapsed_s": round(elapsed, 1),
                    "transfer_time_s": round(transfer_time_s, 3) if transfer_time_s is not None else None,
                    "recv_time_s": round(recv_time_s, 3) if recv_time_s is not None else None,
                    "chaos": chaos,
                    "transfer_bytes": transfer_bytes,
                    "delivery_pct": delivery_pct,
                    "timestamp": datetime.now(UTC).isoformat(),
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
        exit(1)

    _purge_stale_stacks()

    table = Table(title="Capture summary", show_lines=True)
    table.add_column("Protocol", style="cyan", no_wrap=True)
    table.add_column("Transport", style="dim")
    table.add_column("Status")
    table.add_column("Delivery", justify="right")
    table.add_column("Elapsed (s)", justify="right", style="dim")
    table.add_column("Eff.Time (s)", justify="right")

    ok = 0
    for p in protocols:
        r = run_results[p.name]
        status = "[green]OK[/green]" if r["success"] else "[red]FAIL[/red]"
        pct = r.get("delivery_pct")
        if pct is None:
            delivery = "[dim]—[/dim]"
        elif pct >= DELIVERY_GREEN_PCT:
            delivery = f"[green]{pct:.1f}%[/green]"
        elif pct >= DELIVERY_YELLOW_PCT:
            delivery = f"[yellow]{pct:.1f}%[/yellow]"
        else:
            delivery = f"[red]{pct:.1f}%[/red]"
        eff = r.get("transfer_time_s")
        table.add_row(p.name, p.transport, status, delivery, str(r["elapsed_s"]),
                      f"{eff:.3f}" if eff is not None else "[dim]—[/dim]")
        if r["success"]:
            ok += 1

    console.print(table)
    console.print(f"\n{ok}/{len(protocols)} captures succeeded.\n")

    meta_path = captures_dir / "metadata.json"
    meta_path.write_text(dumps(run_results, indent=2))
    console.print(f"Metadata → [dim]{meta_path}[/dim]\n")

    exit(0 if ok == len(protocols) else 1)


if __name__ == "__main__":
    main()
