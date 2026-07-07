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
  _overlay_env modifies environ, which is process-global.  Protocols
  must be run sequentially (as the orchestrator does) to avoid races.
"""

from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from os import environ
from pathlib import Path
from re import search
from threading import Thread
from time import sleep

from python_on_whales import DockerClient, DockerException

COMPOSE_DIR = Path(__file__).parent.parent.parent.parent / "compose"
BASE_COMPOSE = COMPOSE_DIR / "docker-compose.yml"
TEARDOWN_GRACE_S = 15


def _project_name(protocol_name: str) -> str:
    return f"typhoon-eval-{protocol_name.replace('_', '-')}"


def _purge_stale_stacks(current_protocol: str = "") -> None:
    """Force-remove leftover typhoon-eval-* containers and networks."""
    current_prefix = f"typhoon-eval-{current_protocol.replace('_', '-')}-" if current_protocol else ""
    with suppress(Exception):
        dc = DockerClient()
        for container in dc.container.list(all=True, filters={"name": "typhoon-eval-"}):
            if not current_prefix or not container.name.startswith(current_prefix):
                with suppress(Exception):
                    dc.container.remove(container.name, force=True, volumes=True)
        for net in dc.network.list(filters={"name": "typhoon-eval-"}):
            if not current_prefix or not net.name.startswith(current_prefix):
                with suppress(Exception):
                    dc.network.remove(net.name)


@contextmanager
def _overlay_env(extra: dict[str, str]) -> Generator[None, None, None]:
    """Temporarily inject extra variables into the process environment."""
    old = {k: environ.get(k) for k in extra}
    environ.update(extra)
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                environ.pop(k, None)
            else:
                environ[k] = v


# Endpoint values reported by the sender (client log) and sink (server log).
_CLIENT_FIELDS = {
    "rtt_min_ms": (r"rtt_min_ms=([\d.]+)", float),
    "rtt_p50_ms": (r"rtt_p50_ms=([\d.]+)", float),
    "rtt_p95_ms": (r"rtt_p95_ms=([\d.]+)", float),
    "rtt_p99_ms": (r"rtt_p99_ms=([\d.]+)", float),
    "rtt_jitter_ms": (r"rtt_jitter_ms=([\d.]+)", float),
    "roundtrip_delivery_pct": (r"roundtrip_delivery_pct=([\d.]+)", float),
}
_SERVER_FIELDS = {
    "delivery_pct": (r"\((\d+(?:\.\d+)?)%\)", float),
    "received_packets": (r"received (\d+)/\d+ packets", int),
}


def _parse_endpoint_stats(dc: DockerClient, protocol_name: str) -> dict:
    """Extract all endpoint-reported values from the client + server logs.

    Returns a dict with the sink's delivery_pct + received_packets and the
    client's per-packet rtt_* / roundtrip_delivery_pct. Missing keys are None.
    The last match on each line-scan wins.
    """
    stats: dict = dict.fromkeys(
        ("delivery_pct", "received_packets", "rtt_min_ms", "rtt_p50_ms",
         "rtt_p95_ms", "rtt_p99_ms", "rtt_jitter_ms", "roundtrip_delivery_pct")
    )

    def scan(name: str, fields: dict) -> None:
        try:
            logs: str = dc.container.logs(name)
        except Exception:
            return
        for line in logs.splitlines():
            for key, (rx, cast) in fields.items():
                m = search(rx, line)
                if m:
                    stats[key] = cast(m.group(1))

    scan(f"{_project_name(protocol_name)}-client-1", _CLIENT_FIELDS)
    scan(f"{_project_name(protocol_name)}-server-1", _SERVER_FIELDS)
    return stats


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


def _save_logs(dc: DockerClient, protocol_name: str, log_dir: Path) -> None:
    """Write stdout+stderr logs for each compose service to log_dir/<service>.log."""
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        containers = dc.compose.ps(all=True)
    except Exception as e:
        (log_dir / "_error.txt").write_text(f"compose ps failed: {e}\n")
        return
    for container in containers:
        service = container.config.labels.get("com.docker.compose.service", container.name)
        log_path = log_dir / f"{service}.log"
        try:
            raw = dc.container.logs(container.name)
            log_path.write_text(raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace"))
        except Exception as e:
            log_path.write_text(f"[log capture failed: {e}]\n")


def _docker_op(fn: Callable[[], None], timeout_s: int = 60) -> None:
    """Run a docker/compose operation in a daemon thread with a hard timeout."""
    t = Thread(target=fn, daemon=True)
    t.start()
    t.join(timeout=timeout_s)


def compose_up(protocol_name: str, env_file: Path, extra_env: dict[str, str], chaos: bool, timeout: int, log_dir: Path | None = None) -> tuple[bool, dict]:
    """
    Run `docker compose up` for a protocol capture.

    Starts the stack detached (both clean and chaos) and waits for the SERVER
    (sink) container to exit — it is authoritative for delivery and finishes on
    target / DONE / idle-timeout. The client may exit much earlier (an unpaced
    UDP sender empties into the tunnel tx-queue and returns at once), so the
    server, not the client, is what we wait on. Returns True iff the server
    exited with code 0; timeout fires the same teardown.

    Ctrl-C (KeyboardInterrupt) is propagated to the caller; cleanup (stop +
    down) still runs via the finally block so containers and networks are
    always removed.
    """
    dc = _make_client(protocol_name, env_file, chaos)

    _purge_stale_stacks(protocol_name)

    with _overlay_env(extra_env):
        timed_out = False
        success = False
        _up_thread: Thread | None = None

        _docker_op(lambda: dc.compose.down(volumes=True, remove_orphans=True, quiet=True))

        try:
            # Run detached and wait for the SERVER (echo sink) to finish: it is
            # authoritative for delivery and exits on count / idle-timeout.
            try:
                dc.compose.up(detach=True, no_build=True, quiet=True)
            except DockerException:
                timed_out = True

            if not timed_out:
                server_name = f"{_project_name(protocol_name)}-server-1"

                def _wait_server() -> None:
                    with suppress(Exception):
                        dc.container.wait(server_name)

                _up_thread = Thread(target=_wait_server, daemon=True)
                _up_thread.start()
                _up_thread.join(timeout=timeout)

                if _up_thread.is_alive():
                    timed_out = True
                else:
                    client_name = f"{_project_name(protocol_name)}-client-1"

                    def _wait_client() -> None:
                        with suppress(Exception):
                            dc.container.wait(client_name)

                    _client_thread = Thread(target=_wait_client, daemon=True)
                    _client_thread.start()
                    _client_thread.join(timeout=TEARDOWN_GRACE_S)

                _docker_op(lambda: dc.compose.stop(), timeout_s=30)
                # Brief pause so tcpdump flushes its write buffer before down.
                sleep(2)

            if not timed_out:
                try:
                    for container in dc.compose.ps(all=True):
                        service = container.config.labels.get("com.docker.compose.service", "")
                        if service == "server":
                            success = container.state.exit_code == 0
                            break
                except Exception:
                    pass

        finally:
            _docker_op(lambda: dc.compose.stop(), timeout_s=30)
            if _up_thread is not None:
                _up_thread.join(timeout=10)
            stats = _parse_endpoint_stats(dc, protocol_name)
            if log_dir is not None:
                _save_logs(dc, protocol_name, log_dir)
            _docker_op(lambda: dc.compose.down(volumes=True, remove_orphans=True, quiet=True), timeout_s=60)

    return success, stats
