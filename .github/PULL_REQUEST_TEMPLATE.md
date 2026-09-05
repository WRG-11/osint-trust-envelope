<!--
Read CONTRIBUTING.md first. The checklist below mirrors it so a reviewer does
not have to cross-reference a second document.
-->

## What this changes

## Checklist

- [ ] `pytest` green
- [ ] Zero runtime dependencies preserved -- `[project.dependencies]` stays
      empty; anything new goes in an optional extra, never in core
- [ ] A verdict's confidence stays inside its published band
      (`VERDICT_BANDS`); if a band moved, the README table moved with it
- [ ] A demotion is announced (`band_demoted:<from>-><to>`), never silent --
      the library must not assert more than it measured
- [ ] New wrapper: returns through `build_trust()` so the band guard reaches
      it by construction
- [ ] CHANGELOG entry under `[Unreleased]`, and `pyproject.toml` version
      bumped if this is a release
