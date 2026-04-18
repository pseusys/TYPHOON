"""
Docker / Podman helpers for the TYPHOON evaluation harness.

Uses python-on-whales, which provides a unified typed API over both Docker
and Podman.  To run against Podman, point DOCKER_HOST at the Podman socket:

    export DOCKER_HOST=unix:///run/user/1000/podman/podman.sock

IMPORTANT — observer capability requirements:
  The observer container needs NET_ADMIN (sysctl ip_forward) and NET_RAW
  (tcpdump).  Rootless Podman cannot grant real NET_ADMIN, so a rootful
  context is required for the observer to work.  Rootful Podman (podman
  --root) or Docker are both fine; rootless Podman is not.

NOTE — sequential-only:
  _overlay_env modifies os.environ, which is process-global.  Protocols
  must be run sequentially (as the orchestrator does) to avoid races.
"""

import contextlib
import os
import threading
from collections.abc import Generator
from pathlib import Path

from python_on_whales import DockerClient, DockerException

COMPOSE_DIR  = Path(__file__).parent.parent.parent / "compose"
BASE_COMPOSE = COMPOSE_DIR / "docker-compose.yml"


def _project_name(protocol_name: str) -> str:
    return f"typhoon-eval-{protocol_name.replace('_', '-')}"


@contextlib.contextmanager
def _overlay_env(extra: dict[str, str]) -> Generator[None, None, None]:
    """Temporarily inject extra variables into the process environment."""
    old = {k: os.environ.get(k) for k in extra}
    os.environ.update(extra)
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _make_client(protocol_name: str, env_file: Path, chaos: bool) -> DockerClient:
    """
    Build a DockerClient for one protocol run.

    compose_profiles=["chaos"] activates the pumba service (which carries
    profiles: ["chaos"] in the compose file).  When chaos is False the
    profile is not activated and pumba never starts.
    """
    return DockerClient(
        compose_files=[BASE_COMPOSE],
        compose_env_file=str(env_file),
        compose_project_name=_project_name(protocol_name),
        compose_profiles=["chaos"] if chaos else [],
    )


def compose_up(protocol_name: str, env_file: Path, extra_env: dict[str, str], chaos: bool, timeout: int) -> bool:
    """
    Run `docker compose up` for a protocol capture.

    Blocks until the client container exits or the timeout fires, then tears
    down unconditionally.  Returns True iff the client exited with code 0.

    Identifying the client container by the compose service label
    (com.docker.compose.service=client) is robust against project-name
    variations and avoids fragile string-splitting of container names.
    """
    dc = _make_client(protocol_name, env_file, chaos)

    with _overlay_env(extra_env):
        timed_out = False

        def _run_up() -> None:
            try:
                dc.compose.up(abort_on_container_exit=True, no_build=True)
            except DockerException:
                # Expected: observer/server receive SIGTERM when the client
                # exits and --abort-on-container-exit fires; their non-zero
                # exit codes surface here.
                pass

        thread = threading.Thread(target=_run_up, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            timed_out = True
            try:
                dc.compose.stop()
            except DockerException:
                pass
            thread.join(timeout=30)

        # Inspect the client service exit code via container labels.
        success = False
        if not timed_out:
            try:
                for container in dc.compose.ps(all=True):
                    service = container.config.labels.get("com.docker.compose.service", "")
                    if service == "client":
                        success = container.state.exit_code == 0
                        break
            except Exception:
                pass

        try:
            dc.compose.down(volumes=True, remove_orphans=True)
        except DockerException:
            pass

    return success
