# Changelog

All notable changes to `osint-trust-envelope` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Versioning note:** the `[0.1.0]` entry below is seeded from the repository
> history rather than from a tagged release.

## [Unreleased]

### Fixed

- **Systemic crash class, six wrappers**: `wrap_company`, `wrap_ip`,
  `wrap_phone`, `wrap_email`, `wrap_domain`, and `wrap_breach` all extract
  their primary nested sub-fields with the pattern `raw.get("key", {}) or
  {}`. That guards against the field being absent or falsy, but not
  against it being *present with the wrong type* -- a string, list, or
  int where a dict belongs (e.g. an adapter that put an error message in
  `{"validation": "error: timeout"}` instead of the expected shape). The
  next `.get()` call on that value crashes with `AttributeError`,
  defeating the entire point of a library whose job is to be the
  always-answers, never-crashes layer over messy real-world OSINT adapter
  output. Found by systematically passing a non-dict value for every
  wrapper's top-level nested field(s) -- 6 of 15 wrappers crashed, 9 did
  not (they already used `isinstance()` guards for other reasons). Added
  `_safe_dict(value) -> dict` (returns `{}` for anything that is not
  already a dict) and used it at all ~20 affected call sites across the
  six wrappers. Added one crash-safety regression test per wrapper (eight
  total -- two wrappers have more than one affected field). Mutation-
  checked as a batch: temporarily made `_safe_dict` an identity function,
  confirmed all eight new tests fail with the exact `AttributeError`
  above, restored.

- `wrap_email`'s `services_found` and `wrap_domain`'s `ct_logs.count` were
  the only two fields in the whole module coerced with a bare `int(...)`
  -- every other field is read with `.get(..., default)` plus
  `bool()`/`isinstance()` coercion, which cannot raise on a malformed
  adapter payload. A caller passing a non-numeric value in either field
  (e.g. a scraper that put an error string where a count belongs) crashed
  the wrapper with an uncaught `ValueError`, contradicting this library's
  own explicit "never raise, report instead" contract (stated for
  `validate_envelope`, implicit everywhere else via the pervasive
  defensive-coercion pattern). Added `_safe_int()` (falls back to a
  default on `TypeError`/`ValueError`) and used it in both places.
- Same crash class, same two wrappers: `dmarc_policy = (dmarc.get("policy")
  or "").lower()` crashes with `AttributeError` if `policy` is a non-string
  truthy value (int, list, dict) -- `.lower()` does not exist on those
  types. Guarded with `str(...)` first in both `wrap_email` and
  `wrap_domain`.

- `wrap_phone`'s invalid-format early return never referenced its own
  `context` parameter at all -- unlike `wrap_email`'s equivalent early
  return, which calls `_apply_context_cap` purely for the warning tag
  (the confidence, 0.05, is already below every context's cap, so nothing
  clamps). Both wrappers gained `context` support in the same CHANGELOG
  entry ("Deployment-context confidence cap extended to wrap_email,
  wrap_phone, wrap_ip, wrap_domain"), but only email's early return got
  the treatment. A caller in a `gov`/`strict` deployment scanning an
  invalid phone number got an envelope indistinguishable from one with no
  context specified at all -- no `context:gov` warning, nothing to show
  which policy was supposedly in effect. `wrap_ip` and `wrap_domain` have
  no true early return (their all-zero-sources case still flows to the
  shared `_apply_context_cap` call at the end of the function), so this
  was specific to the two wrappers with a `return` inside their bad-input
  branch.

### Added

- CI: lint step (`ruff check .`), `ruff` added to the `dev` extra. Nothing
  in CI previously checked code style/common mistakes beyond `mypy
  --strict`'s type-only view. Currently clean (0 findings) -- this is a
  gate against future drift, not a response to an existing problem.

### Fixed

- `wrap_breach`: the `[0.2.0]` fix below handled `password_check` ok +
  `email_check` attempted-but-errored (surfacing the error, staying
  `VERIFIED`). The mirror case -- `password_check` attempted but errored
  (there is no "skipped" state for the free k-anonymity check; if it was
  requested, it was attempted) + `email_check` fully ok -- still fell
  through to the generic `INFERRED 0.55` branch, silently downgrading a
  genuinely verified email check AND dropping the password error entirely.
  Reproduced: `wrap_breach({"password_check": {"checked": False, "error":
  "network_timeout"}, "email_check": {"checked": True}})` returned
  `inferred 0.55` with `errors == []` and a reasoning bullet claiming
  "No password check completed" -- factually wrong; a check WAS attempted,
  it errored. Added the symmetric `pw_attempted_but_inconclusive` branch
  (mirroring `em_attempted_but_inconclusive`): now returns `VERIFIED 0.93`
  with `"password_check_error: network_timeout"` surfaced in `errors`, and
  the reasoning bullet correctly distinguishes "attempted and inconclusive"
  from "not requested at all". Found by chasing a coverage gap left over
  from the `[0.2.0]` fix -- the async-error branch this fix closes was
  untested, and the CHANGELOG entry for the direction that WAS fixed did
  not mention checking its mirror.

- `wrap_username_scan`: when `strict=True` and a historical-confidence
  provider is wired, the "majority of sites errored" check compared the
  error count (computed *before* strict-mode filtering) against the site
  count *after* strict mode dropped low-confidence "found" hits -- two
  different denominators for the same ratio. Reproduced live: 19 sites
  checked, only 5 (26%) actually errored, but with 10 low-confidence
  "found" hits filtered out, the post-filter count dropped to 9 and
  `5/9 > 50%` reported `unverified` with "5/9 sites errored - majority
  failure invalidates the scan" -- even though 14 of 19 sites (74%)
  responded fine. Confidence-filtering and response-failure are
  independent axes; one must not manufacture the other. The majority-error
  check now uses a `responded_count` computed before strict-mode filtering;
  the post-filter `checked_after`/`found_after` counts are unchanged for
  everything else (the confidence-ratio math and the reported `extra`
  fields), matching this file's existing "Recompute counts AFTER strict
  filter so the UI sees consistent numbers" design.
- `__init__.py`'s `__version__` was `"0.1.1"`, one release behind
  `pyproject.toml`/`CITATION.cff`'s `0.2.0` (tagged 2026-09-05) -- the exact
  bug class the `[0.1.1]` entry below already fixed once (`0.1.0` ->
  `0.1.1`), recurred unguarded for the next release. Synced to `0.2.0`.
  Added `tests/test_version.py`, which reads `pyproject.toml` and
  `CITATION.cff` with a regex (no `tomllib`, since this package supports
  Python 3.10) and asserts both match `__version__` -- so this cannot
  silently drift a third time.
- `SECURITY.md`'s "Supported Versions" table said "Latest release on PyPI"
  as if the package were already published there, contradicting the
  README's own Status section ("not yet published to PyPI"). Reworded to
  "Latest tagged GitHub release" with a note pointing at the README.
- `.coveragerc`'s `fail_under` floor was still 80, its original
  conservative-first-pass value; actual measured coverage is 94% (was 88%
  at the `0.2.0` release per that entry below, drifted further since
  without the floor being ratcheted). Raised to 90.

## [0.2.0] - 2026-09-05

> **First tagged release.** `[0.1.0]` and `[0.1.1]` below were written
> from repository history; neither was ever cut as a Git tag, so until now
> nothing in this repository could be pinned or installed by version, and a
> shipment check had no anchor to measure against. The content below has
> been on `main` since 2026-09-03.

### Added

- **`VERDICT_BANDS` + `_enforce_band()` — the published confidence bands are
  now enforced, in one place, for every wrapper.** The README has documented
  a band per verdict since 0.1.0 (`verified` 0.85-1.00, `inferred` 0.55-0.80,
  `heuristic` 0.25-0.55, `unverified` 0.00-0.20) but only `wrap_username_scan`
  enforced its ceiling, inline. Measured against the table with the guard
  removed, **6 of the 15 wrappers emitted a verdict its own confidence could
  not back**:

  | wrapper | before | violation |
  | --- | --- | --- |
  | `wrap_email` full chain | `inferred 0.84` | 0.04 over the ceiling |
  | `wrap_phone` + numverify | `inferred 0.82` | 0.02 over the ceiling |
  | `wrap_ip` 2 of 3 sources | `verified 0.82` | under the 0.85 floor |
  | `wrap_domain` 2 of 4 sources | `verified 0.80` | under the 0.85 floor |
  | `wrap_username_scan` 3 hits / 40 sites | `inferred 0.469` | inside the *heuristic* band |
  | `wrap_pipeline` (same scan as weakest link) | `inferred 0.458` | propagated |

  The check lives in `build_trust()`, which every wrapper returns through, so
  it reaches all fifteen by construction and cannot fall out of step with a
  newly added one. The two directions are asymmetric on purpose: a confidence
  above the ceiling is **clamped down**, a confidence below the floor
  **demotes the verdict** rather than inflating the number — raising a
  confidence to match its label would have the library assert more than it
  measured. Demotions are announced (`band_demoted:<from>-><to>`), never
  silent. `VERDICT_BANDS` is exported.

- **`validate_envelope(envelope) -> list[str]` — the package's own claim, made
  checkable.** "A verdict never out-claims its source" was something a consumer
  had to take on faith; it is now an assertion they can run on their own side.
  Checks the contract — envelope shape, required trust fields and their types, a
  known verdict, a confidence in 0-1, and the band invariant — and accepts a
  below-floor confidence when a `context_cap:` warning explains it. Never
  raises: malformed input is reported, so it is safe on a payload deserialised
  from JSON or produced by an older version. It deliberately does **not** judge
  whether the verdict is the *right* one for the data; nothing outside the
  caller's adapters can know that, and pretending otherwise would be the same
  overclaim in a new place. Exported.

  Pointed at envelopes produced by the previous release, it independently
  reports all six band violations listed above (6/6 flagged) from the JSON
  alone; against this release, 0/6.

- **`trust.reasoning` is now populated by all 15 wrappers, not 1.** The field
  has existed since 0.1.0 and `build_trust`'s docstring says operators use it
  "to decide whether to trust or manually re-verify a result" — but only
  `wrap_username_scan` ever filled it in, so on fourteen of fifteen code paths
  the documented field was an empty list. Each wrapper now emits up to five
  ordered bullets naming which sources answered, which signal set the ceiling,
  and what held the verdict back — including on the invalid-input early returns,
  where the distinction between "no data" and "a negative result" matters most.
  Measured on a six-wrapper sample: 1/6 before, 6/6 after.

- `wrap_pipeline`: `extra.sub_modules` (named per-module breakdown) and
  `extra.weakest_module`. The aggregate verdict is the weakest link's, but
  `extra.sub_verdicts` was a bare list of verdicts with no names, so a pipeline
  reporting `heuristic` gave an operator nothing to act on — strengthening the
  wrong module would not move the number. `sub_verdicts` keeps its historical
  shape; the breakdown is additive.

- `wrap_pipeline`: unrecognised module names are now named
  (`pipeline_unmapped_modules:<names>` + a reasoning bullet). Dispatch covers 8
  of the 15 wrappers, so a legitimate `paste` or `whois` block silently
  defaulted to `unverified 0.10` and dragged the whole aggregate down, with
  nothing in the envelope to distinguish "this name is not wired up" from "this
  lookup failed".

- Tests: `tests/test_envelope_contract.py` (51 tests) — `validate_envelope`
  against every wrapper × the band grid × every deployment context, its
  violation and malformed-input paths, the bool-is-not-a-number trap, the
  deliberate "does not judge the tradecraft" boundary, and `reasoning` as a
  *reach* test (all wrappers, all inputs, non-empty, ≤5 bullets) rather than
  spot checks — "one wrapper does it" being the state it exists to end.

- Tests: `tests/test_band_invariant.py` (60 tests) — the invariant over a grid
  of every wrapper × representative inputs × every deployment context, the six
  historical violations pinned as regressions, and three *reach* tests: that
  the grid covers every public wrapper, that every wrapper funnels through
  `build_trust`, and that the per-wrapper inline copy of the ceiling has not
  come back. Verified against a control arm (the band table present, the
  enforcement absent): 6 of 15 wrappers fail, 9 pass.

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

- `wrap_username_scan`: the corroboration promotion and the confidence it
  promoted answered to **different denominators**. Promotion qualified on the
  *absolute* number of independent platforms (`>= 3`), while confidence was
  computed from the hit *ratio* (`0.30 + found/checked * 0.25`). On a wide
  scan those diverge: 3 hits across 40 responding sites cleared the platform
  bar at confidence 0.469, so the envelope carried an `inferred` label over a
  number in the *heuristic* band — and scanning **more** sites for the same
  evidence made the confidence **lower**. Sparse-but-wide is the normal shape
  of a real username scan (it is exactly what `wrg_project_osint` feeds in),
  not an edge case. Promotion now additionally requires the boosted confidence
  to reach the `inferred` floor; when it does not, the verdict holds at
  `heuristic` and says why (`corroboration_below_inferred_floor` + a reasoning
  bullet). `_enforce_band` remains the backstop.
- The `inferred` ceiling was re-implemented inline inside `wrap_username_scan`
  (added in `8b69524`, *after* the `wrap_email` / `wrap_phone` ladders it was
  meant to police) and consequently never reached them. That copy is removed
  in favour of the shared check; the two ladders now read their top rung from
  `VERDICT_BANDS[INFERRED][1]` instead of hardcoding 0.84 / 0.82.
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
