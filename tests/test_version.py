"""``__version__`` must agree with ``pyproject.toml``.

This exact drift already happened once: the CHANGELOG's ``[0.1.1]`` entry
records ``__init__.py``'s ``__version__`` sitting at ``"0.1.0"`` -- one
release behind ``pyproject.toml``'s ``0.1.1`` -- and being synced. Nothing
pinned that fix, so it silently reverted: at the ``0.2.0`` tag,
``__version__`` still read ``"0.1.1"``, meaning
``import osint_trust_envelope; osint_trust_envelope.__version__`` reported
the wrong version at runtime for a second time.

Read with a regex rather than ``tomllib`` because this package supports
Python 3.10, and ``tomllib`` only shipped in the standard library from 3.11.
"""
from __future__ import annotations

import re
from pathlib import Path

import osint_trust_envelope

REPO_ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert match, "could not find version = \"...\" in pyproject.toml"
    return match.group(1)


def test_dunder_version_matches_pyproject() -> None:
    assert osint_trust_envelope.__version__ == _pyproject_version()


def test_dunder_version_matches_citation_cff() -> None:
    """CITATION.cff's own version pin has an equivalent mechanical check in
    the WRG shipment-gate tooling (a different repo), but that gate does not
    check __init__.py's __version__ -- this is the local half of the same
    invariant, kept in this repo so it survives on its own."""
    text = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version:\s*([^\s]+)', text)
    assert match, "could not find version: ... in CITATION.cff"
    assert osint_trust_envelope.__version__ == match.group(1)
