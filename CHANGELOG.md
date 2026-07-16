# Changelog

All notable changes to `osint-trust-envelope` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Versioning note:** the `[0.1.0]` entry below is seeded from the repository
> history rather than from a tagged release.

## [Unreleased]

### Added

- README: "Used by" section documenting `wrg_project_osint` integration with
  concrete examples of the zero-hit (clean-negative -> `inferred`) and
  adapter-error (`sites_checked=0` -> `unverified`) conventions.
- Tests: `test_adapter_error_convention_sites_checked_zero` — pins the
  `sites_checked=0` / empty-results pattern as the canonical form for
  signalling scanner failure, distinct from a clean-negative scan.
- Tests: `test_rdap_only_is_inferred` in `TestDomainWrapper` — pins the
  one-of-four-sources case (RDAP-only lookup) as `inferred 0.55`.

- Tests: `tests/test_untested_wrappers.py` (35 tests) — `wrap_avatar`,
  `wrap_company`, `wrap_whois`, `wrap_ssl`, `wrap_paste`, `wrap_metadata`,
  `wrap_generic` previously had zero direct test coverage; measured coverage
  was 79%, below the `.coveragerc` `fail_under=80` floor. Now 88%.
- CI: coverage step (`coverage run` + `coverage report`) now runs after
  pytest and enforces the `.coveragerc` floor — previously `.coveragerc`
  existed but was never invoked, so the floor was unenforced dead config.
  `coverage` added to the `dev` extra.
- Tests: `test_password_ok_email_errored_stays_verified_and_surfaces_error`
  + `test_password_ok_email_errored_matches_no_email_check_confidence` in
  `TestBreachWrapper` — regression coverage for the `wrap_breach` fix below.
- CI: type-check step (`mypy --strict src/osint_trust_envelope/`) — the
  package ships `py.typed` (a promise to downstream type-checkers) but
  nothing verified that promise in CI; it now runs after coverage.
  `mypy` added to the `dev` extra. Currently clean, zero errors.
- **Deployment-context confidence cap extended to `wrap_email`, `wrap_phone`,
  `wrap_ip`, `wrap_domain`** (`context: "default"|"casual"|"strict"|"gov"`,
  keyword-only, defaults to `None`/`"default"` — fully backward compatible).
  Previously only `wrap_username_scan` respected the context profiles
  (`confidence_cap` 1.0/1.0/0.80/0.70); a `gov`/`strict` deployment scanning
  email, phone, IP, or domain data could still claim up to `verified 0.98`
  confidence with no way to cap it. Shared `_apply_context_cap()` helper
  factored out of `wrap_username_scan`'s existing inline logic (behavior
  there is unchanged — same warnings, same clamp) and reused across all
  five wrappers. Tests: `TestContextCapExtendedToOtherWrappers` (9 tests).

### Fixed

- `wrap_breach`: an `email_check` that was **attempted but errored** (not
  skipped, not ok — e.g. a mid-request HIBP timeout) fell through to the
  generic `INFERRED 0.55` branch, silently downgrading a genuinely verified
  password check (which alone should yield `VERIFIED 0.90`, same as no
  email check at all) and dropping the actual email error entirely. Now
  treated the same as "no email data available": `VERIFIED 0.90`, with the
  underlying error surfaced in `trust.errors`.
- `__init__.py`'s `__version__` was `"0.1.0"`, one release behind
  `pyproject.toml`'s `0.1.1` (tagged 2026-06-10) — `import
  osint_trust_envelope; osint_trust_envelope.__version__` reported the
  wrong version at runtime. Synced to `0.1.1`.
- `wrap_pipeline`: confidence collapsed to a static per-verdict anchor
  (e.g. every `INFERRED` pipeline reported `0.68`, regardless of the
  actual weak sub-module's real confidence). Now takes the minimum
  confidence among the sub-modules that landed on the weakest verdict
  tier — two pipelines with the same weakest tier but different real
  strength (e.g. email at 0.60 vs 0.84) no longer report identically.
  Tests: `test_confidence_reflects_the_weak_links_actual_score_not_a_static_anchor`,
  `test_unknown_module_name_defaults_to_unverified_confidence`.
- `ci.yml`: the pinned `actions/checkout` and `actions/setup-python` SHAs
  were already current, but their trailing version comments were stale
  (`# v4` / `# v5` for SHAs that actually resolve to v7.0.0 / v6.3.0 —
  confirmed against `codeql.yml`'s correct `# v7.0.0` comment for the same
  checkout SHA in this repo). Comments corrected; no functional change.

### Changed

- `wrap_username_scan` docstring: added explicit guidance on the two
  no-result states (clean-negative vs adapter-error) that integrators
  commonly conflate.

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
