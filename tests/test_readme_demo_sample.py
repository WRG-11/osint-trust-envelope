"""The README's first screen quotes the demo's output. Hold the quote against the demo.

A sample in a code block is typed by hand and nothing re-runs it, so it can go
stale the day a warning is renamed or a confidence anchor moves. This runs
``demo.py`` and requires the README sample to be a contiguous run of the lines
the demo prints, in the same order.

What it does not check: the README's other examples.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def readme_sample() -> list[str]:
    """The lines of the README's first code block that starts with the demo's case 1."""
    lines = (REPO_ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("[1] ")), None)
    if start is None:
        return []
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("```")), len(lines))
    return lines[start:end]


def demo_output() -> list[str]:
    run = subprocess.run(
        [sys.executable, "demo.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        check=True,
    )
    return run.stdout.splitlines()


def test_readme_quotes_the_demo_verbatim() -> None:
    sample = readme_sample()
    assert len(sample) >= 5, "README no longer quotes the demo's first case; update this test"
    printed = demo_output()
    assert sample[0] in printed, f"the demo no longer prints {sample[0]!r}"
    at = printed.index(sample[0])
    assert printed[at : at + len(sample)] == sample
