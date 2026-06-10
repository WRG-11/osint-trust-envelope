# Changelog

All notable changes to `osint-trust-envelope` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Versioning note:** the `[0.1.0]` entry below is seeded from the repository
> history rather than from a tagged release.

## [Unreleased]

## [0.1.1] - 2026-06-10

Repository-hygiene and CI hardening after the initial `0.1.0` cut; no change to
the public API or the trust-verdict logic.

### Added

- `SECURITY.md` — private vulnerability disclosure via GitHub Security
  Advisories. (784b1c5)
- CI: pytest workflow + README status badges + community-health files.
  (b3de9f4 #5)
- CodeQL static-analysis workflow and a `dependabot.yml` (GitHub Actions + pip,
  weekly). (1e21267, 569f8f8 #2)

### Maintenance

- ci(security): pinned `codeql-action` / `checkout` workflow refs to commit
  SHAs (e50d27b #3); `actions/checkout` 6.0.2 -> 6.0.3 (#4).

## [0.1.0] - 2026-06-01

First public release. Wraps OSINT lookup results in a trust envelope whose
verdict is **capped at the highest level the source _type_ can honestly
support**, moving uncertainty out of analyst headspace and into the result type.

### Added

- **Trust-envelope core** — every lookup is returned as a
  `{"result": ..., "trust": ...}` envelope with a `verdict`, a `confidence`
  score, and structured `warnings`.
- **Per-source-type epistemic ceilings** — source-type-specific caps written
  into the code, not left to caller discipline (e.g. a phone-number wrapper
  structurally cannot return `verified`, by design).
- **Source-type wrappers** for OSINT result types (e.g. `wrap_phone`) that
  apply the verdict ladder and emit honest, anti-overclaim warnings.
- Pre-promotion robustness, encoding, and UX fixes folded into the initial
  release. (bd66538 #1)

### Notes

- Zero-overclaim by design: the package's purpose is to make confident-looking
  OSINT UIs structurally honest about what each signal can support.
