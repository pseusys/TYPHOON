"""Background-blending corpus orchestrator.

For each of N randomised runs:

  1. Sample a profile for TYPHOON (stratified over `PART3_PROFILES`).
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

from datetime import UTC, datetime
from json import dumps
from os import environ
from pathlib import Path
from random import Random
from secrets import randbits
from subprocess import DEVNULL, STDOUT, TimeoutExpired, run

from click import Path as ClickPath
from click import command, option
from jinja2 import Environment, FileSystemLoader, StrictUndefined
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
    PART3_PROFILES,
    PROFILES,
    SERVICE_SLOTS,
    bg_profile_to_env,
    profile_to_env,
)

console = Console()

RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results" / "background"
COMPOSE_DIR = Path(__file__).parent.parent.parent.parent / "compose"
BG_COMPOSE_DIR = Path(__file__).parent.parent.parent.parent / "background" / "compose"
# Jinja2 template for the per-run docker-compose file (one template covers
# observer + TYPHOON + per-generator + optional chaos blocks).
COMPOSE_TEMPLATE_NAME = "per_run.yml.j2"
_COMPOSE_TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(str(BG_COMPOSE_DIR)),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)

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
        result = run(
            ["docker", "compose", "-f", str(compose_file), "build"],
            stdin=DEVNULL,
        )
        if result.returncode != 0:
            console.print(f"[red]docker compose build failed[/red] for {compose_file}")
            raise SystemExit(result.returncode)


def _sample_generators(rng: Random, pool: list[str] | None = None) -> list[str]:
    """Pick a random subset of background generator class names of size ≥ 3.

    *pool* restricts the candidate set (defaulting to ``GENERATOR_WEIGHTS.keys()``).
    When the pool is smaller than ``MIN_GENERATORS_PER_RUN``, the per-run count
    collapses to the pool size so a single-generator filter (e.g. ``--modes unknown``)
    still produces valid runs.
    """
    keys = pool if pool is not None else list(GENERATOR_WEIGHTS.keys())
    if not keys:
        return []
    lo = min(MIN_GENERATORS_PER_RUN, len(keys))
    hi = min(MAX_GENERATORS_PER_RUN, len(keys))
    n = rng.randint(lo, hi)
    return rng.sample(keys, k=n)


def _sample_chaos(rng: Random) -> dict[str, float]:
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


def _stratified_profile_schedule(rng: Random, total_runs: int, pool: list[str] | None = None) -> list[str]:
    """Return a shuffled run-by-run profile list with each profile near-equally represented.

    Each profile gets `total_runs // n_profiles` runs; the remainder (if any)
    is distributed to a random subset of profiles, one extra each.  Then the
    list is shuffled so the corpus interleaves profiles instead of running
    each in a contiguous block (which would hide systematic chaos drift).

    *pool* restricts the candidate TYPHOON profiles (defaulting to ``PART3_PROFILES``
    — excludes ``bulk_upload``, Part 2's operational-comparison-only profile).
    """
    profiles = pool if pool is not None else list(PART3_PROFILES)
    base = total_runs // len(profiles)
    extra = total_runs % len(profiles)
    schedule: list[str] = []
    for p in profiles:
        schedule.extend([p] * base)
    if extra > 0:
        schedule.extend(rng.sample(profiles, min(extra, len(profiles))))
        # If `extra` > pool size, top up with repeats so the schedule reaches `total_runs`.
        while len(schedule) < total_runs:
            schedule.append(rng.choice(profiles))
    rng.shuffle(schedule)
    return schedule


def _parse_modes(modes_spec: str | None) -> tuple[list[str] | None, list[str] | None]:
    """Split ``--modes`` into TYPHOON-profile and bg-generator filters.

    Returns ``(profile_filter, generator_filter)`` where each side is either a
    sorted list (when at least one matching name was given) or ``None``
    (full default pool).  Names that do not match any TYPHOON profile or
    background generator raise ``SystemExit``.
    """
    if not modes_spec:
        return None, None
    requested = [s.strip() for s in modes_spec.split(",") if s.strip()]
    profile_set: set[str] = set()
    generator_set: set[str] = set()
    unknown: list[str] = []
    for name in requested:
        if name in PROFILES:
            profile_set.add(name)
        if name in GENERATOR_WEIGHTS:
            generator_set.add(name)
        if name not in PROFILES and name not in GENERATOR_WEIGHTS:
            unknown.append(name)
    if unknown:
        raise SystemExit(
            f"--modes: unknown name(s) {unknown}.  Valid TYPHOON profiles: "
            f"{sorted(PROFILES)}; valid bg generators: {sorted(GENERATOR_WEIGHTS)}."
        )
    return (sorted(profile_set) or None, sorted(generator_set) or None)


def _render_compose(run_id: str, run_dir: Path, generators: list[str], typhoon_profile: str,
                    profile_env: dict[str, str], bg_envs: dict[str, dict[str, str]],
                    chaos: dict[str, float]) -> Path:
    """Render and write the per-run docker-compose YAML.  Returns the path.

    Loads ``background/compose/per_run.yml.j2`` and supplies it with one
    structured context dict per run.  *profile_env* drives only the TYPHOON
    containers; *bg_envs* maps each selected background generator name to its
    own per-run env dict, sampled independently from ``BACKGROUND_PROFILES``
    so real-X traffic actually looks like real X (not TYPHOON-profile-warped
    X).  The chaos block is rendered only when at least one chaos parameter
    is non-zero — that single qdisc covers `delay+jitter+loss+duplicate+
    reorder` on both observer interfaces (Pumba can't combine them).
    """
    typhoon_slot = SERVICE_SLOTS["typhoon"]
    gen_contexts = [
        {
            "name": gen,
            "image_prefix": "typhoon-eval-bg-" + gen.replace("_", "-"),
            "server_ip": SERVICE_SLOTS[gen].server_ip,
            "client_ip": SERVICE_SLOTS[gen].client_ip,
            "extra_mount": "wg_shared:/shared" if gen == "wireguard_idle" else None,
            "env": bg_envs[gen],
        }
        for gen in generators
    ]
    chaos_context = None
    if any(v > 0.0 for v in chaos.values()):
        chaos_context = {
            "delay_ms":      int(chaos["latency_ms"]),
            "jitter_ms":     int(chaos["jitter_ms"]),
            "loss_pct":      f"{chaos['loss_pct']:.3f}",
            "duplicate_pct": f"{chaos['duplicate_pct']:.3f}",
            "reorder_pct":   f"{chaos['reorder_pct']:.3f}",
        }
    template = _COMPOSE_TEMPLATE_ENV.get_template(COMPOSE_TEMPLATE_NAME)
    rendered = template.render(
        run_id_dashed     = run_id.replace("_", "-"),
        observer_left_ip  = OBSERVER_LEFT_IP,
        observer_right_ip = OBSERVER_RIGHT_IP,
        run_dir_abs       = run_dir.resolve(),
        capture_filter    = "net 172.20.0.0/24 or net 172.21.0.0/24",
        typhoon_server_ip = typhoon_slot.server_ip,
        typhoon_client_ip = typhoon_slot.client_ip,
        profile_env       = profile_env,
        generators        = gen_contexts,
        chaos             = chaos_context,
    )
    compose_path = run_dir / "docker-compose.yml"
    compose_path.write_text(rendered)
    # `typhoon_profile` is intentionally unused here — it's already encoded in
    # `profile_env`'s TRAFFIC_PROFILE key.  Kept in the signature so the caller
    # interface stays unchanged.
    del typhoon_profile
    return compose_path


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--runs", default=DEFAULT_NUM_RUNS, show_default=True, type=int,
              help="Number of randomised corpus runs.")
@option("--seed", default=None, type=int, help="RNG seed (default: random).")
@option("--out-dir", "out_dir", default=str(RESULTS_ROOT), show_default=True, type=ClickPath(),
              help="Root directory for corpus run outputs.")
@option("--chaos/--no-chaos", default=True, show_default=True,
              help="Apply network-wide Pumba chaos (latency/jitter/loss) per run.")
@option("--build/--no-build", default=True, show_default=True,
              help="Rebuild every Docker image used by the corpus before the first run.")
@option("--modes", "modes_spec", default=None, type=str,
              help="Comma-separated list of TYPHOON profile names and/or bg generator names "
                   "to restrict the corpus to (e.g. `raw_default,unknown`).  Names that match "
                   "a TYPHOON profile filter the per-run profile schedule; names that match "
                   "a bg generator filter the per-run generator pool.  Defaults to the full "
                   "stratified schedule + random subset of all bg generators.")
def main(runs: int, seed: int | None, out_dir: str, chaos: bool, build: bool, modes_spec: str | None) -> None:
    """Run the background-blending corpus."""
    profile_pool, generator_pool = _parse_modes(modes_spec)
    if profile_pool or generator_pool:
        console.print(
            f"[dim]--modes filter: TYPHOON profiles = "
            f"{profile_pool if profile_pool else 'ALL'}; "
            f"bg generators = {generator_pool if generator_pool else 'ALL'}.[/dim]"
        )
    if build:
        _build_images()
    rng = Random(seed if seed is not None else randbits(64))
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    schedule = _stratified_profile_schedule(rng, runs, pool=profile_pool)
    console.print(f"[dim]Stratified schedule: {schedule}[/dim]")

    for i, typhoon_profile_name in enumerate(schedule):
        run_id = "run_" + datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
        run_dir = out_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        typhoon_profile = PROFILES[typhoon_profile_name]
        generators = _sample_generators(rng, pool=generator_pool)
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
            "started_at": datetime.now(UTC).isoformat(),
            "typhoon_profile": typhoon_profile_name,
            "generators": generators,
            "chaos": chaos_params,
            "profile_env": profile_env,
            "bg_envs": bg_envs,
            "ip_map": ip_map,
        }
        (run_dir / "metadata.json").write_text(dumps(metadata, indent=2))

        console.print(f"[bold]{i + 1}/{runs}[/bold]  {run_id}  profile={typhoon_profile_name}  generators={generators}  chaos={chaos_params}")

        compose_path = _render_compose(run_id, run_dir, generators, typhoon_profile_name, profile_env, bg_envs, chaos_params)
        log_path = run_dir / "compose.log"

        env = environ.copy()
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
                run(cmd_up, env=env, stdout=lf, stderr=STDOUT,
                               stdin=DEVNULL, timeout=run_timeout)
            except TimeoutExpired:
                lf.write("[corpus] compose up timed out — forcing teardown\n")

        cmd_down = ["docker", "compose", "-f", str(compose_path), "down",
                    "--volumes", "--remove-orphans"]
        with log_path.open("a") as lf:
            lf.write(f"\n$ {' '.join(cmd_down)}\n")
            run(cmd_down, env=env, stdout=lf, stderr=STDOUT, stdin=DEVNULL)

    console.print(f"[green]Corpus complete:[/green] {runs} runs in {out_root}")


if __name__ == "__main__":
    main()
