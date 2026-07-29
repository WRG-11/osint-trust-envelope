"""The verdict/confidence band invariant, and proof that it REACHES.

The library's whole promise is that a verdict label never claims more than the
source type can support. That promise has a numeric half -- the confidence band
each verdict is allowed to occupy -- which was published in the README from day
one and enforced in exactly ONE of the fifteen wrappers.

Measured 2026-07-29, before ``_enforce_band`` existed:

    wrap_email  full chain        inferred 0.84   (ceiling 0.80)
    wrap_phone  + numverify       inferred 0.82   (ceiling 0.80)
    wrap_ip     2 of 3 sources    verified 0.82   (floor   0.85)
    wrap_domain 2 of 4 sources    verified 0.80   (floor   0.85)
    wrap_username_scan  3 of 40   inferred 0.469  (floor   0.55)

Four of those five were invisible to the 152 tests that already existed,
because every test asserted a verdict and a confidence *separately* and none
compared the two. A presence assert cannot catch a pair that is individually
plausible and jointly wrong.

So this file tests three different things, and the third is the one that keeps
the other two honest:

1. the invariant holds for every wrapper over a grid of inputs;
2. the specific historical violations do not come back;
3. the guard is structurally REACHABLE -- every wrapper funnels through
   ``build_trust``, and the grid covers every wrapper that exists. A guard
   installed in one place and a checker that only looks at that place is how
   the original defect survived a full test suite.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from osint_trust_envelope import trust as t

REPO_ROOT = Path(__file__).resolve().parents[1]


# ── the grid ────────────────────────────────────────────────────────────────
#
# Representative raw inputs per wrapper: the empty/absent case, a weak case and
# the strongest case each ladder can express. The strong cases matter most --
# every historical violation was at the TOP of a ladder, where the numbers were
# hand-tuned and nothing cross-checked them against the band.

STRONG_EMAIL = {
    "validation": {
        "format_valid": True, "mx_reachable": True,
        "mx_records": [{"priority": 1, "exchange": "aspmx.l.google.com"}],
        "mx_provider": "Google Workspace",
        "spf": {"present": True, "all_qualifier": "-"},
        "dmarc": {"present": True, "policy": "reject"},
        "disposable": False, "role_account": {"is_role": False},
    },
    "services_found": 3,
}
STRONG_PHONE = {
    "parsed": {"valid": True, "country_code": "+1",
               "enrichment_source": "libphonenumber"},
    "social_checks": [{"platform": "WhatsApp", "possible": True},
                      {"platform": "Telegram", "possible": True}],
    "reverse_lookup": {"lookup_done": True, "carrier": "Example Carrier"},
}


def _scan(checked: int, found: int) -> dict:
    return {
        "sites_checked": checked, "sites_found": found,
        "results": [{"status": "found", "site": f"S{i}"} for i in range(found)]
        + [{"status": "not_found"}] * (checked - found),
    }


GRID: dict[str, list] = {
    "wrap_username_scan": [
        {}, _scan(0, 0), _scan(10, 0), _scan(10, 2), _scan(10, 4), _scan(10, 10),
        # the sparse-but-wide shapes a real scanner actually produces; these are
        # where promotion-by-count and confidence-by-ratio pulled apart.
        _scan(40, 3), _scan(100, 3), _scan(100, 5), _scan(100, 60),
    ],
    "wrap_email": [
        {}, {"validation": {"format_valid": False}},
        {"validation": {"format_valid": True, "mx_reachable": False}},
        {"validation": {"format_valid": True, "mx_reachable": True}},
        STRONG_EMAIL,
    ],
    "wrap_phone": [
        {}, {"parsed": {"valid": False}},
        {"parsed": {"valid": True, "enrichment_source": "regex"}},
        {"parsed": {"valid": True, "enrichment_source": "libphonenumber"}},
        STRONG_PHONE,
    ],
    "wrap_ip": [
        {}, {"geolocation": {}, "rdap": {}, "reverse_dns": {}},
        {"geolocation": {"found": True}, "rdap": {}, "reverse_dns": {}},
        {"geolocation": {"found": True}, "rdap": {"found": True}, "reverse_dns": {}},
        {"geolocation": {"found": True}, "rdap": {"found": True},
         "reverse_dns": {"hostname": "a.b"}},
        {"geolocation": {}, "rdap": {}, "reverse_dns": {}, "tor": {"is_tor": True}},
    ],
    "wrap_domain": [
        {}, {"dns": {}, "rdap": {}, "ssl": {}, "http": {}},
        {"rdap": {"found": True}, "dns": {}, "ssl": {}, "http": {}},
        {"rdap": {"found": True}, "ssl": {"has_ssl": True}, "dns": {}, "http": {}},
        {"dns": {"a_records": ["1.2.3.4"]}, "rdap": {"found": True},
         "ssl": {"has_ssl": True}, "http": {"reachable": True},
         "dnssec": {"checked": True, "validated": True},
         "ct_logs": {"checked": True, "count": 9}},
    ],
    "wrap_breach": [
        {}, {"password_check": {"checked": True}},
        {"password_check": {"checked": True}, "email_check": {"checked": True}},
        {"password_check": {"checked": True}, "email_check": {"skipped": True}},
        {"password_check": {"checked": False, "error": "x"},
         "email_check": {"checked": False, "error": "y"}},
    ],
    "wrap_avatar": [{}, {"results": []}, {"results": [{"found": True}] * 9}],
    "wrap_company": [{}, {"domain": "acme.example"},
                     {"github": {"found": True, "login": "acme"}}],
    "wrap_paste": [{}, {"results": []}, {"results": [{"url": "x"}] * 3},
                   {"results": [{"url": "x"}] * 50}],
    "wrap_name": [{}, {"username_candidates": ["a", "b"]}],
    "wrap_whois": [{}, {"registrar": "Example"}, {"found": True}],
    "wrap_ssl": [{}, {"has_ssl": True}, {"certificate": {"subject": "CN=x"}}],
    "wrap_metadata": [{}, {"error": "unsupported"}, {"width": 100, "height": 100}],
    "wrap_generic": [{}, ["a", "list"]],
    "wrap_pipeline": [
        {}, {"modules": {}},
        {"modules": {"ip": {"geolocation": {"found": True}, "rdap": {"found": True},
                            "reverse_dns": {"hostname": "a.b"}}}},
        {"modules": {"ip": {"geolocation": {"found": True}, "rdap": {"found": True},
                            "reverse_dns": {"hostname": "a.b"}},
                     "email": STRONG_EMAIL,
                     "username_scan": _scan(100, 3)}},
        {"modules": {"unknown_future_module": {"x": 1}}},
    ],
}

_CONTEXT_AWARE = ("wrap_username_scan", "wrap_email", "wrap_phone",
                  "wrap_ip", "wrap_domain")


def _public_wrappers() -> dict:
    import osint_trust_envelope as pkg
    return {n: getattr(pkg, n) for n in pkg.__all__ if n.startswith("wrap_")}


def _assert_in_band(name: str, raw, block: dict) -> None:
    verdict, conf = block["verdict"], block["confidence"]
    low, high = t.VERDICT_BANDS[verdict]
    assert low <= conf <= high, (
        f"{name}{'' if not isinstance(raw, dict) else ''} returned "
        f"{verdict!r} with confidence {conf}, outside its band {low}-{high}. "
        f"raw={raw!r}"
    )


# ── 1. the invariant, everywhere ────────────────────────────────────────────

@pytest.mark.parametrize("name", sorted(GRID))
def test_every_wrapper_output_stays_inside_its_verdict_band(name: str) -> None:
    fn = _public_wrappers()[name]
    for raw in GRID[name]:
        _assert_in_band(name, raw, fn(raw)["trust"])


@pytest.mark.parametrize("name", sorted(_CONTEXT_AWARE))
@pytest.mark.parametrize("context", t.VALID_CONTEXTS + ("not-a-context", None))
def test_the_invariant_survives_every_deployment_context(name: str, context) -> None:
    """A context cap lowers the number; it must not push a result out of band.

    The cap is allowed to keep a `verified` verdict at 0.70 -- that exemption is
    the documented contract -- so the assertion here is the ceiling plus the
    explicit policy-cap escape, not a blanket range check.
    """
    fn = _public_wrappers()[name]
    for raw in GRID[name]:
        block = fn(raw, context=context)["trust"]
        verdict, conf = block["verdict"], block["confidence"]
        low, high = t.VERDICT_BANDS[verdict]
        assert conf <= high, f"{name} ctx={context} {verdict} {conf} > {high}"
        if conf < low:
            assert any(w.startswith("context_cap:") for w in block["warnings"]), (
                f"{name} ctx={context} fell below the {verdict} floor without a "
                f"policy cap to explain it: {block['warnings']}"
            )


# ── 2. the specific violations, pinned ──────────────────────────────────────

def test_sparse_wide_scan_no_longer_wears_an_inferred_label() -> None:
    """3 hits across 40 responding sites: the shape wrg_project_osint feeds in.

    Promotion qualified on the absolute platform count while the confidence was
    computed from the hit ratio, so the label said `inferred` over a number in
    the *heuristic* band.
    """
    block = t.wrap_username_scan(_scan(40, 3))["trust"]
    assert block["verdict"] == t.HEURISTIC
    assert block["confidence"] < t.VERDICT_BANDS[t.INFERRED][0]
    assert "corroboration_below_inferred_floor" in block["warnings"]
    # ...and it says so, rather than leaving the operator to wonder why three
    # independent platforms did not earn a promotion.
    assert any("under the 'inferred' band floor" in r for r in block["reasoning"])


def test_a_dense_scan_still_earns_the_promotion() -> None:
    """The floor check must not have quietly disabled promotion altogether."""
    block = t.wrap_username_scan(_scan(10, 4))["trust"]
    assert block["verdict"] == t.INFERRED
    assert "cross_adapter_corroboration_promotion" in block["warnings"]


@pytest.mark.parametrize("name,raw", [
    ("wrap_email", STRONG_EMAIL),
    ("wrap_phone", STRONG_PHONE),
])
def test_top_of_ladder_no_longer_overshoots_the_inferred_ceiling(name, raw) -> None:
    """Both ladders hand-coded a top rung above the published ceiling (0.84 and
    0.82 against 0.80). They now read the ceiling from the band table."""
    block = _public_wrappers()[name](raw)["trust"]
    assert block["verdict"] == t.INFERRED
    assert block["confidence"] == t.VERDICT_BANDS[t.INFERRED][1]


# ── 3. the doctrine: both directions claim LESS ─────────────────────────────

def test_a_floor_violation_demotes_rather_than_inflating_the_number() -> None:
    """Raising a confidence to meet its label would make the library assert
    more than it measured -- the exact failure it exists to prevent."""
    verdict, conf = t._enforce_band(t.VERIFIED, 0.40, [])
    assert conf == 0.40, "the number must not move upward to satisfy the label"
    assert verdict == t.HEURISTIC


def test_a_ceiling_violation_lowers_the_number_not_the_label() -> None:
    verdict, conf = t._enforce_band(t.INFERRED, 0.99, [])
    assert verdict == t.INFERRED
    assert conf == t.VERDICT_BANDS[t.INFERRED][1]


def test_a_dead_zone_confidence_lands_on_the_lower_bands_ceiling() -> None:
    """0.82 sits below `verified`'s floor AND above `inferred`'s ceiling, so no
    band holds it. Searching by floor alone demotes the label and leaves the
    number out of band -- which is the bug the first cut of _enforce_band
    shipped with, caught by this grid rather than by review."""
    verdict, conf = t._enforce_band(t.VERIFIED, 0.82, [])
    assert verdict == t.INFERRED
    assert conf == t.VERDICT_BANDS[t.INFERRED][1] == 0.80


def test_a_demotion_is_announced_never_silent() -> None:
    warnings: list[str] = []
    t._enforce_band(t.VERIFIED, 0.40, warnings)
    assert "band_demoted:verified->heuristic" in warnings


def test_a_policy_cap_lowers_the_number_but_keeps_the_verdict() -> None:
    """README: the cap "only affects confidence, never the verdict tier
    itself". A gov deployment must still learn that RDAP answered."""
    block = t.wrap_ip(
        {"geolocation": {"found": True}, "rdap": {"found": True},
         "reverse_dns": {"hostname": "a.b"}},
        context="gov",
    )["trust"]
    assert block["verdict"] == t.VERIFIED
    assert block["confidence"] == 0.70
    assert not any(w.startswith("band_demoted:") for w in block["warnings"])


# ── 4. REACH: the part that keeps the rest honest ───────────────────────────

def test_the_grid_covers_every_public_wrapper() -> None:
    """A wrapper added without a grid entry would be exempt from the invariant
    while the suite still reported green -- which is precisely how the original
    single-wrapper guard survived 152 passing tests."""
    missing = sorted(set(_public_wrappers()) - set(GRID))
    assert not missing, f"wrappers with no band-grid coverage: {missing}"


def test_every_public_wrapper_funnels_through_build_trust(monkeypatch) -> None:
    """The guard lives in build_trust, so its reach IS the funnel. If some
    wrapper ever hand-rolls its own trust dict, the invariant silently stops
    applying to it and nothing else in the suite would notice."""
    seen: list[str] = []
    real = t.build_trust

    def spy(**kwargs):
        seen.append(kwargs.get("method", "?"))
        return real(**kwargs)

    monkeypatch.setattr(t, "build_trust", spy)
    for name, fn in sorted(_public_wrappers().items()):
        seen.clear()
        fn(GRID[name][-1])
        assert seen, f"{name} produced a trust block without calling build_trust"


def test_the_band_guard_is_not_reimplemented_per_wrapper() -> None:
    """The pre-fix code enforced the ceiling inline inside wrap_username_scan.
    A second copy is how the two halves drift apart again."""
    src = (REPO_ROOT / "src" / "osint_trust_envelope" / "trust.py").read_text(
        encoding="utf-8")
    code = "\n".join(
        line for line in src.splitlines() if not line.lstrip().startswith("#")
    )
    assert code.count("def _enforce_band") == 1
    assert "inferred_band_cap" not in code, "the inline copy came back"


# ── 5. the table itself ─────────────────────────────────────────────────────

def test_bands_are_ordered_strongest_to_weakest() -> None:
    order = [t.VERIFIED, t.INFERRED, t.HEURISTIC, t.UNVERIFIED]
    floors = [t.VERDICT_BANDS[v][0] for v in order]
    ceils = [t.VERDICT_BANDS[v][1] for v in order]
    assert floors == sorted(floors, reverse=True)
    assert ceils == sorted(ceils, reverse=True)
    assert set(t.VERDICT_BANDS) == t.VALID_VERDICTS


def test_default_anchors_sit_inside_their_own_bands() -> None:
    for verdict, anchor in t._CONF_ANCHOR.items():
        low, high = t.VERDICT_BANDS[verdict]
        assert low <= anchor <= high, f"{verdict} anchor {anchor} out of band"


def test_readme_publishes_exactly_the_bands_the_code_enforces() -> None:
    """The README table is the contract a consumer reads. Documentation drift
    here is not cosmetic -- it is the contract and the enforcement disagreeing,
    which is the state this whole file exists to end."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    row = re.compile(
        r"^\|\s*`(verified|inferred|heuristic|unverified)`\s*\|.*?\|"
        r"\s*([01]\.\d{2})\s*-\s*([01]\.\d{2})\s*\|",
        re.MULTILINE,
    )
    documented = {m.group(1): (float(m.group(2)), float(m.group(3)))
                  for m in row.finditer(readme)}
    assert documented, "could not find the verdict-ladder table in README.md"
    assert documented == t.VERDICT_BANDS
