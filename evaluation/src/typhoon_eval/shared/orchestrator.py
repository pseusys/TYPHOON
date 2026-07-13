"""TYPHOON evaluation orchestrator.

For each selected protocol, runs a Docker Compose capture session, waits for
the client to finish transferring, then tears down. The observer writes
results/captures/<protocol>[_chaos].pcap.

Per-run profile values (sampled from `shared/profiles.py`) are passed to
client and server containers as TRAFFIC_PROFILE + PROFILE_* env vars.
"""

from datetime import UTC, datetime
from json import dumps
from pathlib import Path
from random import Random
from sys import exit

from click import Choice, command, option
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .console import console
from .docker_utils import COMPOSE_DIR, _purge_stale_stacks, compose_up
from .profiles import DEFAULT_PROFILE, PROFILES, profile_to_env
from .protocols import ALL, BY_NAME, Protocol

RESULTS_DIR = Path(__file__).parent.parent.parent.parent / "results"

MIN_PCAP_SIZE_B = 100
DELIVERY_GREEN_PCT = 99.9
DELIVERY_YELLOW_PCT = 80.0
ENV_DIR = COMPOSE_DIR / "env"
TYPHOON_DRAIN_CHANNEL_CAPACITY = 81_920
IDLE_TIMEOUT_S = 30
LATENCY_COUNT = 500
LATENCY_INTERVAL_MS = 20
LATENCY_SIZE = 256
LATENCY_RECV_TIMEOUT_MS = 5000


def _run_one(
    protocol: Protocol,
    chaos: bool,
    timeout: int,
    profile_env: dict[str, str],
    loss_pct: float,
    bw_mbps: float,
    captures_dir: Path,
    log_dir: Path,
) -> tuple[bool, str, dict]:
    """
    Run a single protocol capture.
    Returns (success, error_message, endpoint_stats) — see _parse_endpoint_stats.
    """
    env_file = ENV_DIR / f".env.{protocol.name}"
    if not env_file.exists():
        return False, f"missing env file: {env_file}", {}

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
        "TYPHOON_DRAIN_CHANNEL_CAPACITY": str(TYPHOON_DRAIN_CHANNEL_CAPACITY),
        "IDLE_TIMEOUT_S": str(IDLE_TIMEOUT_S),
        "LAT_COUNT": str(LATENCY_COUNT),
        "LAT_INTERVAL_MS": str(LATENCY_INTERVAL_MS),
        "LAT_SIZE": str(LATENCY_SIZE),
        "LAT_RECV_TIMEOUT_MS": str(LATENCY_RECV_TIMEOUT_MS),
    }
    extra_env.update(profile_env)

    success, stats = compose_up(
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
            return False, "observer did not write pcap", stats
        if pcap.stat().st_size < MIN_PCAP_SIZE_B:
            return False, f"pcap is empty ({pcap.stat().st_size} bytes)", stats

    return success, "" if success else "non-zero exit or timeout", stats


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
    help="Per-protocol timeout in seconds before the run is killed. The latency ping is short in clean mode; under chaos its sequential RTTs stretch it, so leave headroom.",
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
    default=2.0,
    show_default=True,
    type=float,
    help="Chaos: packet loss percentage applied by the netem sidecar (default 2% matches the sidecar's standalone default).",
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

    console.print(f"\n[bold]TYPHOON evaluation{chaos_note}[/bold]")
    console.print(f"  Protocols : {', '.join(p.name for p in protocols)}")
    console.print(f"  Timeout   : {timeout}s per run (env file may override per protocol)")
    console.print(f"  Latency   : {LATENCY_COUNT} × {LATENCY_SIZE} B probes @ {LATENCY_INTERVAL_MS} ms")
    console.print(f"  Profile   : {profile}  ({profile_obj.description})")
    if chaos and (loss_pct > 0 or bw_mbps > 0):
        console.print(f"  Chaos     : loss={loss_pct}%  bw={bw_mbps or 'unlimited'} Mbps")
    console.print()

    run_id = "run_" + datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    captures_dir = RESULTS_DIR / "captures" / run_id
    captures_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"  Run ID    : [dim]{run_id}[/dim]\n")

    transfer_bytes = LATENCY_COUNT * LATENCY_SIZE
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
        "latency": {
            "count": LATENCY_COUNT,
            "interval_ms": LATENCY_INTERVAL_MS,
            "size_b": LATENCY_SIZE,
        },
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

                success, error, stats = _run_one(
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
                    "chaos": chaos,
                    "transfer_bytes": transfer_bytes,
                    "timestamp": datetime.now(UTC).isoformat(),
                    **stats,
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
        captured = [k for k in run_results if not k.startswith("_")]
        succeeded = sum(1 for k in captured if run_results[k].get("success"))
        run_results["_notice"] = {
            "aborted": True,
            "reason": "KeyboardInterrupt",
            "protocols_total": len(protocols),
            "protocols_attempted": len(captured),
            "protocols_succeeded": succeeded,
            "message": (
                f"Run interrupted before completion — {succeeded}/{len(protocols)} protocols "
                f"captured. Partial artifact retained intentionally (aborted run, not a protocol bug)."
            ),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        meta_path = captures_dir / "metadata.json"
        meta_path.write_text(dumps(run_results, indent=2))
        console.print(f"\n[yellow]Interrupted — containers cleaned up. Partial metadata → [dim]{meta_path}[/dim][/yellow]")
        exit(1)

    _purge_stale_stacks()

    table = Table(title="Capture summary", show_lines=True)
    table.add_column("Protocol", style="cyan", no_wrap=True)
    table.add_column("Transport", style="dim")
    table.add_column("Status")
    table.add_column("Delivery", justify="right")
    table.add_column("Elapsed (s)", justify="right", style="dim")
    table.add_column("RTT p50/p95 (ms)", justify="right")

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
        p50, p95 = r.get("rtt_p50_ms"), r.get("rtt_p95_ms")
        perf = f"{p50:.2f} / {p95:.2f}" if p50 is not None and p95 is not None else "[dim]—[/dim]"
        table.add_row(p.name, p.transport, status, delivery, str(r["elapsed_s"]), perf)
        if r["success"]:
            ok += 1

    console.print(table)
    console.print(f"\n{ok}/{len(protocols)} captures succeeded.\n")

    complete = ok == len(protocols)
    run_results["_notice"] = {
        "aborted": False,
        "complete": complete,
        "protocols_total": len(protocols),
        "protocols_succeeded": ok,
        "message": (
            f"{ok}/{len(protocols)} protocols captured successfully."
            + ("" if complete else " Partial run — some protocols failed; artifact retained intentionally.")
        ),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    meta_path = captures_dir / "metadata.json"
    meta_path.write_text(dumps(run_results, indent=2))
    console.print(f"Metadata → [dim]{meta_path}[/dim]\n")

    exit(0 if ok == len(protocols) else 1)


if __name__ == "__main__":
    main()
