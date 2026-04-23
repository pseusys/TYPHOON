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
import re
import time
import threading
from collections.abc import Generator
from pathlib import Path

from python_on_whales import DockerClient, DockerException

COMPOSE_DIR = Path(__file__).parent.parent.parent / "compose"
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


def _parse_delivery(dc: DockerClient, protocol_name: str) -> float | None:
    """Extract the delivery percentage from the server container's logs."""
    server_name = f"{_project_name(protocol_name)}-server-1"
    try:
        logs: str = dc.container.logs(server_name)
        for line in reversed(logs.splitlines()):
            m = re.search(r"\((\d+(?:\.\d+)?)%\)", line)
            if m:
                return float(m.group(1))
    except Exception:
        pass
    return None


def _make_client(protocol_name: str, env_file: Path, chaos: bool) -> DockerClient:
    """
    Build a DockerClient for one protocol run.

    compose_profiles=["chaos"] activates the chaos service (which carries
    profiles: ["chaos"] in the compose file).  When chaos is False the
    profile is not activated and chaos never starts.
    """
    return DockerClient(
        compose_files=[BASE_COMPOSE],
        compose_env_files=[env_file],
        compose_project_name=_project_name(protocol_name),
        compose_profiles=["chaos"] if chaos else [],
    )


def compose_up(protocol_name: str, env_file: Path, extra_env: dict[str, str], chaos: bool, timeout: int) -> tuple[bool, float | None]:
    """
    Run `docker compose up` for a protocol capture.

    Non-chaos: blocks until the client container exits or timeout fires, then
    tears down.  Returns True iff the client exited with code 0.

    Chaos: starts the stack detached so that the client can exit while the
    chaos service keeps draining the netem queue to the server.  Polls until
    the server exits (it finishes or hits idle-timeout), then tears down.
    Returns True iff the client exited with code 0.

    Ctrl-C (KeyboardInterrupt) is propagated to the caller; cleanup (stop +
    down) still runs via the finally block so containers and networks are
    always removed.
    """
    dc = _make_client(protocol_name, env_file, chaos)

    with _overlay_env(extra_env):
        timed_out = False
        success = False
        _up_thread: threading.Thread | None = None

        try:
            dc.compose.down(volumes=True, remove_orphans=True, quiet=True)
        except DockerException:
            pass

        try:
            if not chaos:
                def _run_up() -> None:
                    try:
                        dc.compose.up(abort_on_container_exit=True, no_build=True, quiet=True)
                    except DockerException:
                        pass

                _up_thread = threading.Thread(target=_run_up, daemon=True)
                _up_thread.start()
                _up_thread.join(timeout=timeout)

                if _up_thread.is_alive():
                    timed_out = True
                    try:
                        dc.compose.stop()
                    except DockerException:
                        pass
                    _up_thread.join(timeout=30)

            else:
                try:
                    dc.compose.up(detach=True, no_build=True, quiet=True)
                except DockerException:
                    timed_out = True

                if not timed_out:
                    server_name = f"{_project_name(protocol_name)}-server-1"

                    def _wait_server() -> None:
                        try:
                            dc.container.wait(server_name)
                        except Exception:
                            pass

                    _up_thread = threading.Thread(target=_wait_server, daemon=True)
                    _up_thread.start()
                    _up_thread.join(timeout=timeout)

                    if _up_thread.is_alive():
                        timed_out = True

                    try:
                        dc.compose.stop()
                    except DockerException:
                        pass
                    # Brief pause so tcpdump flushes its write buffer before down.
                    time.sleep(2)

            if not timed_out:
                try:
                    for container in dc.compose.ps(all=True):
                        service = container.config.labels.get("com.docker.compose.service", "")
                        if service == "client":
                            success = container.state.exit_code == 0
                            break
                except Exception:
                    pass

        finally:
            try:
                dc.compose.stop()
            except DockerException:
                pass
            if _up_thread is not None:
                _up_thread.join(timeout=10)
            delivery_pct = _parse_delivery(dc, protocol_name)
            try:
                dc.compose.down(volumes=True, remove_orphans=True, quiet=True)
            except DockerException:
                pass

    return success, delivery_pct
