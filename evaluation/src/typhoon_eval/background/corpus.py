"""Background-blending corpus orchestrator.

For each of N randomised runs:

  1. Sample a profile for TYPHOON (uniform over `PROFILES`).
  2. Sample a subset of background generators of size ≥ 3 (uniform).
  3. Sample chaos parameters (latency, jitter, loss) bounded by §A.6.
  4. Allocate per-service IP slots from `SERVICE_SLOTS`.
  5. Render a docker-compose YAML referencing all selected services + the
     observer, plus a Pumba container for the network-wide chaos.
  6. `compose up` the stack, capture for the run duration, then `compose down`.
  7. Write per-run metadata.json with the IP→class mapping for the labeller.

Outputs: `results/background/run_<timestamp>/{capture.pcap, metadata.json,
config.json, logs/}`.
"""

from __future__ import annotations

import datetime
import json
import os
import random
import secrets
import subprocess
from pathlib import Path

import click
from rich.console import Console

from typhoon_eval.shared.profiles import (
    BACKGROUND_PROFILES,
    CHAOS_DUPLICATE_PCT,
    CHAOS_JITTER_FRACTION,
    CHAOS_LATENCY_MS,
    CHAOS_LOSS_PCT,
    CHAOS_REORDER_PCT,
    GENERATOR_WEIGHTS,
    OBSERVER_LEFT_IP,
    OBSERVER_RIGHT_IP,
    PROFILES,
    SERVICE_SLOTS,
    bg_profile_to_env,
    profile_to_env,
)

console = Console()

RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results" / "background"
COMPOSE_DIR = Path(__file__).parent.parent.parent.parent / "compose"
BG_COMPOSE_DIR = Path(__file__).parent.parent.parent.parent / "background" / "compose"

# Build-compose YAMLs covering every image the corpus runs need:
#   * shared/observer + typhoon-server/client → compose/docker-compose.build.yml
#   * per-class background generators → background/compose/docker-compose.build.yml
BUILD_COMPOSE_FILES = [
    COMPOSE_DIR / "docker-compose.build.yml",
    BG_COMPOSE_DIR / "docker-compose.build.yml",
]

DEFAULT_NUM_RUNS = 70
MIN_GENERATORS_PER_RUN = 3
MAX_GENERATORS_PER_RUN = 6


def _build_images() -> None:
    """Rebuild every image the corpus runs need.  Aborts on build failure."""
    for compose_file in BUILD_COMPOSE_FILES:
        if not compose_file.exists():
            console.print(f"[red]Build compose file missing:[/red] {compose_file}")
            raise SystemExit(1)
        console.print(f"[bold]Building images[/bold] from {compose_file}")
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "build"],
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            console.print(f"[red]docker compose build failed[/red] for {compose_file}")
            raise SystemExit(result.returncode)


def _sample_generators(rng: random.Random) -> list[str]:
    """Pick a random subset of background generator class names of size ≥ 3."""
    n = rng.randint(MIN_GENERATORS_PER_RUN, MAX_GENERATORS_PER_RUN)
    keys = list(GENERATOR_WEIGHTS.keys())
    return rng.sample(keys, k=n)


def _sample_chaos(rng: random.Random) -> dict[str, float]:
    """Sample chaos parameters such that pumba's `jitter < latency` invariant holds.

    Pumba rejects the netem invocation when jitter ≥ latency.  Sampling jitter
    independently from a fixed range produced ~10 % failed runs; instead we
    sample latency first and bound jitter to a fraction of it.
    """
    latency_ms = CHAOS_LATENCY_MS.sample(rng)
    jitter_fraction = CHAOS_JITTER_FRACTION.sample(rng)
    return {
        "latency_ms":    latency_ms,
        "jitter_ms":     latency_ms * jitter_fraction,
        "loss_pct":      CHAOS_LOSS_PCT.sample(rng),
        "duplicate_pct": CHAOS_DUPLICATE_PCT.sample(rng),
        "reorder_pct":   CHAOS_REORDER_PCT.sample(rng),
    }


def _stratified_profile_schedule(rng: random.Random, total_runs: int) -> list[str]:
    """Return a shuffled run-by-run profile list with each profile near-equally represented.

    Each profile gets `total_runs // n_profiles` runs; the remainder (if any)
    is distributed to a random subset of profiles, one extra each.  Then the
    list is shuffled so the corpus interleaves profiles instead of running
    each in a contiguous block (which would hide systematic chaos drift).
    """
    profiles = list(PROFILES.keys())
    base = total_runs // len(profiles)
    extra = total_runs % len(profiles)
    schedule: list[str] = []
    for p in profiles:
        schedule.extend([p] * base)
    if extra > 0:
        schedule.extend(rng.sample(profiles, extra))
    rng.shuffle(schedule)
    return schedule


def _render_compose(run_id: str, run_dir: Path, generators: list[str], typhoon_profile: str,
                    profile_env: dict[str, str], bg_envs: dict[str, dict[str, str]],
                    chaos: dict[str, float]) -> Path:
    """Write the per-run docker-compose YAML.  Returns the path.

    *profile_env* drives only the TYPHOON containers.  *bg_envs* maps each
    selected background generator name to its own per-run env dict, sampled
    independently from ``BACKGROUND_PROFILES`` so real-X traffic actually
    looks like real X (not TYPHOON-profile-warped X).
    """
    compose_path = run_dir / "docker-compose.yml"
    services_lines = []

    services_lines.append(_observer_block(run_dir))
    services_lines.append(_typhoon_blocks(typhoon_profile, profile_env))

    for gen in generators:
        services_lines.append(_generator_block(gen, bg_envs[gen]))

    # Replace pumba with the dedicated chaos container.  Pumba's `netem
    # delay` subcommand can't combine loss in a single qdisc; the chaos
    # container shares the observer's network namespace and writes a
    # combined `delay+jitter+loss` qdisc on both observer interfaces, so
    # both c2s and s2c packets actually take the sampled chaos.
    if any(v > 0.0 for v in chaos.values()):
        services_lines.append(_chaos_block(chaos))

    yaml = _compose_header(run_id) + "\n".join(s for s in services_lines if s)
    compose_path.write_text(yaml)
    return compose_path


def _compose_header(run_id: str) -> str:
    return (
        f"name: typhoon-eval-bg-{run_id.replace('_', '-')}\n\n"
        "volumes:\n"
        "  eval_keys: {}\n"
        "  wg_shared: {}\n\n"
        "networks:\n"
        "  net_left:\n"
        "    driver: bridge\n"
        "    ipam:\n"
        "      config:\n"
        "        - subnet: 172.20.0.0/24\n"
        "  net_right:\n"
        "    driver: bridge\n"
        "    ipam:\n"
        "      config:\n"
        "        - subnet: 172.21.0.0/24\n\n"
        "services:\n\n"
    )


def _observer_block(run_dir: Path) -> str:
    # Capture every flow on either /24 — covers every service slot, not just TYPHOON.
    capture_filter = "net 172.20.0.0/24 or net 172.21.0.0/24"
    return (
        "  observer:\n"
        "    image: typhoon-eval-observer\n"
        "    networks:\n"
        f"      net_left:  {{ ipv4_address: {OBSERVER_LEFT_IP} }}\n"
        f"      net_right: {{ ipv4_address: {OBSERVER_RIGHT_IP} }}\n"
        "    privileged: true\n"
        "    pid: \"host\"\n"
        "    sysctls:\n"
        "      - net.ipv4.ip_forward=1\n"
        "      - net.ipv6.conf.all.disable_ipv6=1\n"
        "    volumes:\n"
        f"      - {run_dir.resolve()}:/captures\n"
        "    environment:\n"
        "      PROTOCOL: background\n"
        "      PROTOCOL_SUFFIX: \"\"\n"
        f"      CAPTURE_FILTER: \"{capture_filter}\"\n"
    )


def _profile_env_yaml(profile_env: dict[str, str], indent: str = "      ") -> str:
    return "".join(f"{indent}{k}: \"{v}\"\n" for k, v in profile_env.items())


def _typhoon_blocks(typhoon_profile: str, profile_env: dict[str, str]) -> str:
    slot = SERVICE_SLOTS["typhoon"]
    env = _profile_env_yaml(profile_env)
    grace = "    stop_grace_period: 5s\n"
    return (
        "  typhoon-server:\n"
        "    image: typhoon-eval-typhoon-server\n"
        "    networks:\n"
        f"      net_right: {{ ipv4_address: {slot.server_ip} }}\n"
        "    cap_add: [NET_ADMIN]\n"
        "    devices: [/dev/net/tun:/dev/net/tun]\n"
        "    sysctls: [net.ipv6.conf.all.disable_ipv6=1]\n"
        "    volumes: [eval_keys:/keys]\n"
        f"{grace}"
        "    environment:\n"
        f"      OBSERVER_GW: {OBSERVER_RIGHT_IP}\n"
        f"      CERT_HOST: {slot.server_ip}\n"
        f"{env}"
        "    depends_on: [observer]\n\n"
        "  typhoon-client:\n"
        "    image: typhoon-eval-typhoon-client\n"
        "    networks:\n"
        f"      net_left: {{ ipv4_address: {slot.client_ip} }}\n"
        "    cap_add: [NET_ADMIN]\n"
        "    devices: [/dev/net/tun:/dev/net/tun]\n"
        "    sysctls: [net.ipv6.conf.all.disable_ipv6=1]\n"
        "    volumes: [eval_keys:/keys]\n"
        f"{grace}"
        "    environment:\n"
        f"      OBSERVER_GW: {OBSERVER_LEFT_IP}\n"
        f"{env}"
        "    depends_on: [typhoon-server]\n"
    )


def _generator_block(gen: str, profile_env: dict[str, str]) -> str:
    slot = SERVICE_SLOTS[gen]
    env = _profile_env_yaml(profile_env)
    image_prefix = "typhoon-eval-bg-" + gen.replace("_", "-")
    # WireGuard idle uses a shared volume to swap public keys between client and server.
    extra_mounts = "    volumes: [wg_shared:/shared]\n" if gen == "wireguard_idle" else ""
    grace = "    stop_grace_period: 5s\n"
    return (
        f"  {gen}-server:\n"
        f"    image: {image_prefix}-server\n"
        "    networks:\n"
        f"      net_right: {{ ipv4_address: {slot.server_ip} }}\n"
        "    cap_add: [NET_ADMIN]\n"
        "    sysctls: [net.ipv6.conf.all.disable_ipv6=1]\n"
        f"{extra_mounts}"
        f"{grace}"
        "    environment:\n"
        f"      OBSERVER_GW: {OBSERVER_RIGHT_IP}\n"
        f"      SERVER_HOST: {slot.server_ip}\n"
        f"{env}"
        "    depends_on: [observer]\n\n"
        f"  {gen}-client:\n"
        f"    image: {image_prefix}-client\n"
        "    networks:\n"
        f"      net_left: {{ ipv4_address: {slot.client_ip} }}\n"
        "    cap_add: [NET_ADMIN]\n"
        "    sysctls: [net.ipv6.conf.all.disable_ipv6=1]\n"
        f"{extra_mounts}"
        f"{grace}"
        "    environment:\n"
        f"      OBSERVER_GW: {OBSERVER_LEFT_IP}\n"
        f"      SERVER_HOST: {slot.server_ip}\n"
        f"{env}"
        f"    depends_on: [{gen}-server]\n"
    )


def _chaos_block(chaos: dict[str, float]) -> str:
    """Chaos sidecar that shares the observer's network namespace and applies a
    single `delay + jitter + loss + duplicate + reorder` netem qdisc on both
    observer interfaces.

    Combines every netem perturbation in one qdisc so packets are subject to
    all of them simultaneously (vs pumba, which can only apply one chaos type
    per invocation and would conflict if stacked).  Both directions (left +
    right) get the same qdisc so c2s and s2c packets see identical chaos.
    """
    return (
        "  chaos:\n"
        "    init: true\n"
        "    image: typhoon-eval-chaos\n"
        "    network_mode: \"service:observer\"\n"
        "    cap_add:\n"
        "      - NET_ADMIN\n"
        "    environment:\n"
        f"      CHAOS_DELAY_MS: \"{int(chaos['latency_ms'])}\"\n"
        f"      CHAOS_JITTER_MS: \"{int(chaos['jitter_ms'])}\"\n"
        f"      CHAOS_LOSS_PCT: \"{chaos['loss_pct']:.3f}\"\n"
        f"      CHAOS_DUPLICATE_PCT: \"{chaos['duplicate_pct']:.3f}\"\n"
        f"      CHAOS_REORDER_PCT: \"{chaos['reorder_pct']:.3f}\"\n"
        "      CHAOS_BW_MBPS: \"0\"\n"
        "    depends_on: [observer]\n"
        "    stop_grace_period: 5s\n"
    )


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--runs", default=DEFAULT_NUM_RUNS, show_default=True, type=int,
              help="Number of randomised corpus runs.")
@click.option("--seed", default=None, type=int, help="RNG seed (default: random).")
@click.option("--out-dir", "out_dir", default=str(RESULTS_ROOT), show_default=True, type=click.Path(),
              help="Root directory for corpus run outputs.")
@click.option("--chaos/--no-chaos", default=True, show_default=True,
              help="Apply network-wide Pumba chaos (latency/jitter/loss) per run.")
@click.option("--build/--no-build", default=True, show_default=True,
              help="Rebuild every Docker image used by the corpus before the first run.")
def main(runs: int, seed: int | None, out_dir: str, chaos: bool, build: bool) -> None:
    """Run the background-blending corpus."""
    if build:
        _build_images()
    rng = random.Random(seed if seed is not None else secrets.randbits(64))
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    schedule = _stratified_profile_schedule(rng, runs)
    console.print(f"[dim]Stratified schedule: {schedule}[/dim]")

    for i, typhoon_profile_name in enumerate(schedule):
        run_id = "run_" + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S_%f")
        run_dir = out_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        typhoon_profile = PROFILES[typhoon_profile_name]
        generators = _sample_generators(rng)
        chaos_params = _sample_chaos(rng) if chaos else {"latency_ms": 0.0, "jitter_ms": 0.0, "loss_pct": 0.0}
        profile_env = profile_to_env(typhoon_profile, rng)
        bg_envs = {gen: bg_profile_to_env(BACKGROUND_PROFILES[gen], rng) for gen in generators}

        def _slot_dict(name: str) -> dict[str, str | int]:
            slot = SERVICE_SLOTS[name]
            return {
                "name": slot.name,
                "suffix": slot.suffix,
                "client_ip": slot.client_ip,
                "server_ip": slot.server_ip,
            }

        ip_map = {"typhoon": _slot_dict("typhoon")}
        for gen in generators:
            ip_map[gen] = _slot_dict(gen)

        metadata = {
            "run_id": run_id,
            "started_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "typhoon_profile": typhoon_profile_name,
            "generators": generators,
            "chaos": chaos_params,
            "profile_env": profile_env,
            "bg_envs": bg_envs,
            "ip_map": ip_map,
        }
        (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

        console.print(f"[bold]{i + 1}/{runs}[/bold]  {run_id}  profile={typhoon_profile_name}  generators={generators}  chaos={chaos_params}")

        compose_path = _render_compose(run_id, run_dir, generators, typhoon_profile_name, profile_env, bg_envs, chaos_params)
        log_path = run_dir / "compose.log"

        env = os.environ.copy()
        # Cap total time per run at the longest active container's duration
        # (TYPHOON or any bg generator) plus buffer for handshake / teardown.
        max_duration = max(
            float(profile_env["PROFILE_DURATION_S"]),
            *(float(e["PROFILE_DURATION_S"]) for e in bg_envs.values()),
        ) if bg_envs else float(profile_env["PROFILE_DURATION_S"])
        run_timeout = max_duration + 90.0
        cmd_up = ["docker", "compose", "-f", str(compose_path), "up",
                  "--abort-on-container-exit", "--no-build"]
        with log_path.open("a") as lf:
            lf.write(f"\n$ {' '.join(cmd_up)} (timeout {run_timeout:.0f}s)\n")
            try:
                subprocess.run(cmd_up, env=env, stdout=lf, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, timeout=run_timeout)
            except subprocess.TimeoutExpired:
                lf.write("[corpus] compose up timed out — forcing teardown\n")

        cmd_down = ["docker", "compose", "-f", str(compose_path), "down",
                    "--volumes", "--remove-orphans"]
        with log_path.open("a") as lf:
            lf.write(f"\n$ {' '.join(cmd_down)}\n")
            subprocess.run(cmd_down, env=env, stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)

    console.print(f"[green]Corpus complete:[/green] {runs} runs in {out_root}")


if __name__ == "__main__":
    main()
