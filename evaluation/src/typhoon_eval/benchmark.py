"""Rust-level performance benchmarks: cargo bench + example flamegraphs.

Linux only — flamegraphs need `perf` and `cargo-flamegraph`, neither of which
is portable to macOS/Windows. Mirrors `.github/workflows/benchmarks.yaml`.

Outputs: `<out-dir>/bench-{roundtrip,handshake}.txt` (bencher format) and, per
example, `<out-dir>/flamegraphs/<example>.{svg,pdf}` — the interactive SVG
from `cargo flamegraph` (search/zoom via embedded JS) plus a static PDF
rendered from it via `rsvg-convert` (for embedding in reports/papers). If
`rsvg-convert` isn't installed, only the `.svg` is produced.
"""

from __future__ import annotations

from os import environ
from pathlib import Path
from platform import system
from shutil import which
from subprocess import DEVNULL, STDOUT, run

from click import ClickException, command, option
from click import Path as ClickPath
from rich.console import Console

console = Console()

TYPHOON_ROOT = Path(__file__).parent.parent.parent.parent / "typhoon"
BENCH_KEY    = TYPHOON_ROOT / ".bench_keys" / "server_fast.key"
DEFAULT_OUT  = Path(__file__).parent.parent.parent.parent / "artifacts" / "benchmark"

_BENCHES = ("roundtrip", "handshake")
_EXAMPLES = (
    "hello_world", "multi_flow", "multi_client", "client_pool", "long_session",
    "heavy_traffic", "use_case", "mirror_decoy", "flat_iat_decoy", "mimic_probe",
)


def _run(label: str, cmd: list[str], env: dict[str, str] | None = None, capture: Path | None = None) -> bool:
    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
    run_env = {**environ, **env} if env else None
    if capture:
        with capture.open("w") as fh:
            result = run(cmd, cwd=TYPHOON_ROOT, env=run_env, stdin=DEVNULL, stdout=fh, stderr=STDOUT)
    else:
        result = run(cmd, cwd=TYPHOON_ROOT, env=run_env, stdin=DEVNULL)
    if result.returncode != 0:
        console.print(f"  [red]✗ {label} failed (exit {result.returncode})[/red]")
    return result.returncode == 0


def _svg_to_pdf(svg_path: Path) -> bool:
    """Render a same-named .pdf from *svg_path* via rsvg-convert, keeping the .svg too."""
    pdf_path = svg_path.with_suffix(".pdf")
    return _run(f"svg2pdf-{svg_path.stem}", ["rsvg-convert", "-f", "pdf", "-o", str(pdf_path), str(svg_path)])


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--out-dir", default=str(DEFAULT_OUT), show_default=True, type=ClickPath(),
              help="Directory for bench-*.txt and flamegraphs/*.{svg,pdf}.")
def main(out_dir: str) -> None:
    """Run `cargo bench` (roundtrip, handshake) and generate example flamegraphs.

    Requires Linux with `perf` and `cargo-flamegraph` already installed —
    this does not install system packages or touch `perf_event_paranoid`
    (see the CI workflow for the one-time host setup).
    """
    if system() != "Linux":
        raise ClickException("benchmark requires Linux (perf + cargo-flamegraph) — skipping.")

    out_root = Path(out_dir)
    flame_dir = out_root / "flamegraphs"
    out_root.mkdir(parents=True, exist_ok=True)
    flame_dir.mkdir(parents=True, exist_ok=True)
    BENCH_KEY.parent.mkdir(parents=True, exist_ok=True)

    console.print("[cyan]Generating benchmark server key[/cyan]")
    if not _run(
        "gen-key",
        ["cargo", "run", "--quiet", "--bin", "typhoon-gen-key", "--no-default-features",
         "--features", "fast_software,server,tokio,clap", "--", str(BENCH_KEY)],
        env={"RUSTFLAGS": "-D warnings"},
    ):
        raise ClickException("Key generation failed.")

    bench_env = {"TYPHOON_TEST_SERVER_KEY_FAST": str(BENCH_KEY)}
    for name in _BENCHES:
        console.print(f"\n[cyan]cargo bench[/cyan] {name}")
        _run(
            f"bench-{name}",
            ["cargo", "bench", "--bench", name, "--", "--output-format", "bencher"],
            env=bench_env,
            capture=out_root / f"bench-{name}.txt",
        )

    console.print("\n[cyan]flamegraphs[/cyan]")
    flame_env = {"RUSTFLAGS": "-D warnings"}
    has_rsvg = which("rsvg-convert") is not None
    if not has_rsvg:
        console.print("  [yellow]rsvg-convert not found — flamegraphs will stay .svg-only (install librsvg2-bin to also get .pdf).[/yellow]")

    def _flamegraph(label: str, cmd: list[str], svg_path: Path) -> None:
        if not _run(label, cmd, env=flame_env):
            return
        if has_rsvg and not _svg_to_pdf(svg_path):
            console.print(f"  [yellow]⚠ Could not render {svg_path.with_suffix('.pdf').name} — keeping .svg only[/yellow]")

    for example in _EXAMPLES:
        svg_path = flame_dir / f"{example}.svg"
        _flamegraph(f"flamegraph-{example}", ["cargo", "flamegraph", "--example", example, "-o", str(svg_path)], svg_path)

    debug_svg = flame_dir / "debug_probe.svg"
    _flamegraph(
        "flamegraph-debug_probe",
        ["cargo", "flamegraph", "--example", "debug_probe", "--features", "debug", "-o", str(debug_svg)],
        debug_svg,
    )

    console.print(f"\n[green]Benchmark artifacts →[/green] {out_root}")


if __name__ == "__main__":
    main()
