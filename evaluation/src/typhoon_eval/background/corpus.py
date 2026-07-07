"""Background-blending corpus orchestrator.

For each of N runs, every `PART3_PROFILES` TYPHOON mimicry profile and every
`BACKGROUND_PROFILES` class (incl. `unknown`) run concurrently — no per-run
sampling of which classes/profiles participate, so no class is ever absent
from a run its peers are in.  Every class/profile contributes exactly one
flow per run it appears in, except `raw_default`/`tuned_default`: they
exercise the protocol's genuine auto-fill flow selection (see
`eval_client.rs`), so a given run of either may contribute 1–3 flows instead
of exactly 1 — the analyzer's per-flow feature extraction and
`GroupKFold`-by-run-id grouping both already handle that (see
`ml_blending.py::_per_flow_features`/`_load_corpus`).

  1. Sample per-run parameters for every TYPHOON profile and every background
     class independently (each still draws its own random shape per run).
  2. Sample chaos parameters (latency, jitter, loss) bounded by §A.6.
  3. Allocate per-service IP slots from `SERVICE_SLOTS`.
  4. Render a docker-compose YAML referencing every service + the observer,
     plus a Pumba container for the network-wide chaos.
  5. `compose up` the stack, capture for the run duration, then `compose down`.
  6. Write per-run metadata.json with the IP→class mapping for the labeller.

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

from typhoon_eval.shared.console import console
from typhoon_eval.shared.profiles import (
    BACKGROUND_PROFILES,
    CHAOS_DUPLICATE_PCT,
    CHAOS_JITTER_FRACTION,
    CHAOS_LATENCY_MS,
    CHAOS_LOSS_PCT,
    CHAOS_REORDER_PCT,
    OBSERVER_LEFT_IP,
    OBSERVER_RIGHT_IP,
    PART3_PROFILES,
    PROFILES,
    SERVICE_SLOTS,
    TYPHOON_CLASS,
    bg_profile_to_env,
    profile_to_env,
)

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


def _parse_modes(modes_spec: str | None) -> tuple[list[str] | None, list[str] | None]:
    """Split ``--modes`` into TYPHOON-profile and bg-generator filters.

    Returns ``(profile_filter, generator_filter)`` where each side is either a
    sorted list (when at least one matching name was given) or ``None`` (run
    every ``PART3_PROFILES`` / ``BACKGROUND_PROFILES`` entry, the default).
    A given filter, when present, is the *complete* fixed set used every run
    — not a sampling candidate pool, since every run now includes everything
    in it.  Names that do not match any TYPHOON profile or background
    generator raise ``SystemExit``.
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
        if name in BACKGROUND_PROFILES:
            generator_set.add(name)
        if name not in PROFILES and name not in BACKGROUND_PROFILES:
            unknown.append(name)
    if unknown:
        raise SystemExit(
            f"--modes: unknown name(s) {unknown}.  Valid TYPHOON profiles: "
            f"{sorted(PROFILES)}; valid bg generators: {sorted(BACKGROUND_PROFILES)}."
        )
    return (sorted(profile_set) or None, sorted(generator_set) or None)


def _render_compose(run_id: str, run_dir: Path, generators: list[str], typhoon_profiles: list[str],
                    typhoon_envs: dict[str, dict[str, str]], bg_envs: dict[str, dict[str, str]],
                    chaos: dict[str, float]) -> Path:
    """Render and write the per-run docker-compose YAML.  Returns the path.

    Loads ``background/compose/per_run.yml.j2`` and supplies it with one
    structured context dict per run.  *typhoon_envs* maps each TYPHOON
    profile to its own per-run env dict, and *bg_envs* maps each background
    generator name to its own — both sampled independently from
    ``PART3_PROFILES``/``BACKGROUND_PROFILES`` so real-X traffic actually
    looks like real X (not TYPHOON-profile-warped X), and every TYPHOON
    profile runs its own shape independent of its siblings.  Every TYPHOON
    pair gets a dedicated ``eval_keys_<profile>`` volume — they can't share
    the single ``eval_keys`` volume the way one pair could, since each
    server writes its own cert to the same in-container path.  The chaos
    block is rendered only when at least one chaos parameter is non-zero —
    that single qdisc covers `delay+jitter+loss+duplicate+reorder` on both
    observer interfaces (Pumba can't combine them).
    """
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
    typhoon_contexts = [
        {
            "name": tp,
            "server_ip": SERVICE_SLOTS[tp].server_ip,
            "client_ip": SERVICE_SLOTS[tp].client_ip,
            "env": typhoon_envs[tp],
        }
        for tp in typhoon_profiles
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
        typhoon_profiles  = typhoon_contexts,
        generators        = gen_contexts,
        chaos             = chaos_context,
    )
    compose_path = run_dir / "docker-compose.yml"
    compose_path.write_text(rendered)
    return compose_path


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--runs", default=DEFAULT_NUM_RUNS, show_default=True, type=int,
              help="Number of corpus runs (each captures every TYPHOON profile + background class).")
@option("--seed", default=None, type=int, help="RNG seed (default: random).")
@option("--out-dir", "out_dir", default=str(RESULTS_ROOT), show_default=True, type=ClickPath(),
              help="Root directory for corpus run outputs.")
@option("--chaos/--no-chaos", default=True, show_default=True,
              help="Apply network-wide Pumba chaos (latency/jitter/loss) per run.")
@option("--build/--no-build", default=True, show_default=True,
              help="Rebuild every Docker image used by the corpus before the first run.")
@option("--modes", "modes_spec", default=None, type=str,
              help="Comma-separated list of TYPHOON profile names and/or bg generator names "
                   "to restrict the corpus to (e.g. `raw_default,unknown`).  Every name that "
                   "matches a TYPHOON profile or bg generator runs in every corpus run "
                   "(no per-run sampling).  Defaults to every `PART3_PROFILES` profile + "
                   "every `BACKGROUND_PROFILES` class.")
def main(runs: int, seed: int | None, out_dir: str, chaos: bool, build: bool, modes_spec: str | None) -> None:
    """Run the background-blending corpus."""
    profile_pool, generator_pool = _parse_modes(modes_spec)
    typhoon_profiles = profile_pool if profile_pool is not None else list(PART3_PROFILES)
    generators = generator_pool if generator_pool is not None else list(BACKGROUND_PROFILES)
    console.print(
        f"[dim]Every run: TYPHOON profiles = {typhoon_profiles}; "
        f"bg generators = {generators}.[/dim]"
    )
    if build:
        _build_images()
    rng = Random(seed if seed is not None else randbits(64))
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)

    for i in range(runs):
        run_id = "run_" + datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
        run_dir = out_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        chaos_params = _sample_chaos(rng) if chaos else {"latency_ms": 0.0, "jitter_ms": 0.0, "loss_pct": 0.0}
        typhoon_envs = {tp: profile_to_env(PROFILES[tp], rng) for tp in typhoon_profiles}
        bg_envs = {gen: bg_profile_to_env(BACKGROUND_PROFILES[gen], rng) for gen in generators}

        def _slot_dict(name: str) -> dict[str, str | int]:
            slot = SERVICE_SLOTS[name]
            return {
                "name": slot.name,
                "suffix": slot.suffix,
                "client_ip": slot.client_ip,
                "server_ip": slot.server_ip,
            }

        # `class` disambiguates TYPHOON entries (keyed by profile name, since
        # every profile runs concurrently and dict keys must be unique) from
        # background entries (keyed by class name, class == key).  `profile`
        # is only meaningful on TYPHOON entries.
        ip_map = {gen: {**_slot_dict(gen), "class": gen} for gen in generators}
        ip_map.update({
            tp: {**_slot_dict(tp), "class": TYPHOON_CLASS, "profile": tp}
            for tp in typhoon_profiles
        })

        metadata = {
            "run_id": run_id,
            "started_at": datetime.now(UTC).isoformat(),
            "typhoon_profiles": typhoon_profiles,
            "generators": generators,
            "chaos": chaos_params,
            "typhoon_envs": typhoon_envs,
            "bg_envs": bg_envs,
            "ip_map": ip_map,
        }
        (run_dir / "metadata.json").write_text(dumps(metadata, indent=2))

        console.print(f"[bold]{i + 1}/{runs}[/bold]  {run_id}  chaos={chaos_params}")

        compose_path = _render_compose(run_id, run_dir, generators, typhoon_profiles, typhoon_envs, bg_envs, chaos_params)
        log_path = run_dir / "compose.log"

        env = environ.copy()
        # Cap total time per run at the longest active container's duration
        # (any TYPHOON profile or bg generator) plus buffer for handshake / teardown.
        max_duration = max(
            *(float(e["PROFILE_DURATION_S"]) for e in typhoon_envs.values()),
            *(float(e["PROFILE_DURATION_S"]) for e in bg_envs.values()),
        )
        run_timeout = max_duration + 90.0
        # No --abort-on-container-exit: every sender/sink here exits on its own
        # once its own transfer completes (or on idle-timeout/SIGTERM), and
        # this run concurrently mixes ~17 services with wildly different
        # sampled durations.
        cmd_up = ["docker", "compose", "-f", str(compose_path), "up", "--no-build"]
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
