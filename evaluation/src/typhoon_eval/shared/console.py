"""Shared ``rich`` console — widens automatically off a real terminal.

``rich.console.Console()`` auto-detects the terminal width via
``shutil.get_terminal_size()``, which falls back to a hardcoded 80 columns
whenever stdout isn't a real TTY — e.g. GitHub Actions' log streaming, or any
other redirected/piped output. Our summary tables (analysis, capture,
detectability, blending, …) have enough columns that 80 columns wraps almost
every cell onto several lines, producing the mangled tables seen in CI logs.

Every module that prints a table should import ``console`` from here instead
of constructing its own ``Console()``, so this fix applies everywhere at once.
"""

from sys import stdout

from rich.console import Console

# Wide enough that every existing summary table (7 columns, some with
# multi-value cells like "p5/p50/p95") renders on one line per row.
CI_FALLBACK_WIDTH = 200

console = Console(width=None if stdout.isatty() else CI_FALLBACK_WIDTH)
