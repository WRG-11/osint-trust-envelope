"""The envelope contract: `validate_envelope()` and the `reasoning` field.

Two gaps this file closes, both of the same shape -- the package computed
something and then nobody could read it:

* ``build_trust`` has accepted a ``reasoning`` list since 0.1.0 and its own
  docstring says operators use it "to decide whether to trust or manually
  re-verify a result". Exactly **one** of the fifteen wrappers ever filled it
  in; the other fourteen returned ``[]``, so on almost every code path the
  documented field was an empty promise.
* the package's central claim -- a verdict never out-claims its source -- was
  something a consumer had to take on faith. ``validate_envelope`` turns it
  into an assertion they can run.

The reasoning tests are deliberately written as REACH tests (all wrappers, all
grid inputs) rather than as a handful of spot checks, because "one wrapper does
it" is the exact state this file exists to end.
"""
from __future__ import annotations

import pytest

from osint_trust_envelope import trust as t
from osint_trust_envelope import validate_envelope

# The band grid is the canonical corpus of representative inputs. Importing it
# rather than restating it keeps the two files from drifting apart -- a second
# copy of a fixture set rots the same way a second copy of a guard does.
from test_band_invariant import GRID, _public_wrappers


# ── validate_envelope: real output is clean ─────────────────────────────────

@pytest.mark.parametrize("name", sorted(GRID))
def test_every_wrapper_produces_an_envelope_that_validates(name: str) -> None:
    fn = _public_wrappers()[name]
    for raw in GRID[name]:
        problems = validate_envelope(fn(raw))
        assert problems == [], f"{name} raw={raw!r} -> {problems}"


@pytest.mark.parametrize("context", t.VALID_CONTEXTS)
def test_context_capped_envelopes_validate_too(context: str) -> None:
    """A gov cap parks `verified` at 0.70, below its own floor. That is the one
    legal way out of band, and the validator has to know it -- otherwise the
    library's own documented feature would fail its own checker."""
    env = t.wrap_ip(
        {"geolocation": {"found": True}, "rdap": {"found": True},
         "reverse_dns": {"hostname": "a.b"}},
        context=context,
    )
    assert validate_envelope(env) == []


# ── validate_envelope: violations are reported ──────────────────────────────

def test_an_out_of_band_confidence_is_reported() -> None:
    env = {"result": {}, "trust": {
        "verdict": t.INFERRED, "confidence": 0.93, "method": "m",
        "source": "s", "warnings": [], "errors": [], "reasoning": []}}
    problems = validate_envelope(env)
    assert any("exceeds the inferred ceiling" in p for p in problems)


def test_a_below_floor_confidence_without_a_policy_cap_is_reported() -> None:
    env = {"result": {}, "trust": {
        "verdict": t.VERIFIED, "confidence": 0.40, "method": "m",
        "source": "s", "warnings": [], "errors": [], "reasoning": []}}
    problems = validate_envelope(env)
    assert any("below the verified floor" in p for p in problems)


def test_a_below_floor_confidence_with_a_policy_cap_is_accepted() -> None:
    env = {"result": {}, "trust": {
        "verdict": t.VERIFIED, "confidence": 0.70, "method": "m",
        "source": "s", "warnings": ["context_cap:0.70"], "errors": [],
        "reasoning": []}}
    assert validate_envelope(env) == []


def test_an_unknown_verdict_is_reported() -> None:
    env = {"result": {}, "trust": {
        "verdict": "probably", "confidence": 0.5, "method": "m",
        "source": "s", "warnings": [], "errors": [], "reasoning": []}}
    assert any("not one of" in p for p in validate_envelope(env))


@pytest.mark.parametrize("bad,expected", [
    ("not an envelope", "expected dict"),
    ({"trust": {}}, "missing 'result' key"),
    ({"result": {}}, "'trust' is NoneType"),
    ({"result": {}, "trust": []}, "'trust' is list"),
])
def test_malformed_input_is_reported_never_raised(bad, expected: str) -> None:
    """It runs on payloads that came off the wire, so it must not be the thing
    that crashes the consumer it was added to protect."""
    problems = validate_envelope(bad)
    assert problems and any(expected in p for p in problems)


def test_missing_and_mistyped_trust_fields_are_reported() -> None:
    env = {"result": {}, "trust": {
        "verdict": t.INFERRED, "confidence": 0.6,
        "warnings": "not-a-list", "errors": [1, 2], "reasoning": []}}
    problems = validate_envelope(env)
    assert any("trust.method is missing" in p for p in problems)
    assert any("trust.source is missing" in p for p in problems)
    assert any("trust.warnings is str" in p for p in problems)
    assert any("trust.errors must contain only strings" in p for p in problems)


def test_a_bool_confidence_is_not_mistaken_for_a_number() -> None:
    """``isinstance(True, int)`` is True in Python, so a bool would sail past a
    naive numeric check and then compare as 1.0."""
    env = {"result": {}, "trust": {
        "verdict": t.VERIFIED, "confidence": True, "method": "m",
        "source": "s", "warnings": [], "errors": [], "reasoning": []}}
    assert any("expected a number" in p for p in validate_envelope(env))


def test_it_does_not_judge_whether_the_verdict_is_the_right_one() -> None:
    """A well-formed envelope claiming `verified 0.95` for a coin flip passes.

    Nothing outside the caller's adapters can know the verdict is wrong, and a
    validator that pretended to would be the same overclaim in a new place.
    This pins that boundary so nobody 'improves' it into a truth oracle.
    """
    env = {"result": {"coin": "heads"}, "trust": {
        "verdict": t.VERIFIED, "confidence": 0.95, "method": "vibes",
        "source": "a hunch", "warnings": [], "errors": [], "reasoning": []}}
    assert validate_envelope(env) == []


# ── reasoning: reach ────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", sorted(GRID))
def test_every_wrapper_explains_itself_on_every_input(name: str) -> None:
    """1 of 15 wrappers used to fill this in. All 15 now do, on every branch --
    including the early returns for malformed input, which are the paths an
    operator is most likely to be staring at when they need the explanation."""
    fn = _public_wrappers()[name]
    for raw in GRID[name]:
        block = fn(raw)["trust"]
        assert block["reasoning"], (
            f"{name} produced a verdict with no reasoning. raw={raw!r}")
        assert all(isinstance(r, str) and r.strip() for r in block["reasoning"])
        assert len(block["reasoning"]) <= 5, "reasoning is a summary, not a log"


def test_reasoning_survives_the_invalid_input_early_returns() -> None:
    """Both wrappers bail out before their ladder runs; that is precisely when
    a caller needs to be told the difference between 'no data' and 'negative'."""
    for block in (t.wrap_email({"validation": {"format_valid": False}})["trust"],
                  t.wrap_phone({"parsed": {"valid": False}})["trust"]):
        assert block["reasoning"]
        joined = " ".join(block["reasoning"]).lower()
        assert "not" in joined


# ── reasoning: the pipeline names its weak link ─────────────────────────────

def test_pipeline_names_the_module_that_set_the_verdict() -> None:
    """`sub_verdicts` was a bare list of verdicts with no module names, so an
    aggregate of `heuristic` told the operator nothing they could act on."""
    env = t.wrap_pipeline({"modules": {
        "ip": {"geolocation": {"found": True}, "rdap": {"found": True},
               "reverse_dns": {"hostname": "a.b"}},
        "phone": {"parsed": {"valid": True}},
    }})
    block = env["trust"]
    assert block["verdict"] == t.HEURISTIC
    assert block["extra"]["weakest_module"] == "phone"
    assert any("'phone' is the weak link" in r for r in block["reasoning"])
    named = {m["module"] for m in block["extra"]["sub_modules"]}
    assert named == {"ip", "phone"}


def test_pipeline_weakest_module_is_the_lowest_within_the_weakest_tier() -> None:
    """Two modules can share the weakest tier; the one that sets the number is
    the one that must be named, or the operator strengthens the wrong link."""
    env = t.wrap_pipeline({"modules": {
        "company": {"github": {"found": True}},            # inferred 0.70
        "avatar": {"results": [{"found": True}]},          # inferred 0.65
    }})
    block = env["trust"]
    assert block["verdict"] == t.INFERRED
    assert block["confidence"] == 0.65
    assert block["extra"]["weakest_module"] == "avatar"


def test_an_unmapped_module_name_says_so_instead_of_just_reading_unverified() -> None:
    """`wrap_pipeline` dispatches 8 of the 15 wrappers by name. A legitimate
    `paste` block is not among them, so it defaults to unverified 0.10 and
    drags the whole aggregate down -- previously with nothing in the envelope
    to distinguish "this name is not wired up" from "this lookup failed".
    """
    block = t.wrap_pipeline({"modules": {
        "ip": {"geolocation": {"found": True}, "rdap": {"found": True},
               "reverse_dns": {"hostname": "a.b"}},
        "paste": {"results": [{"url": "x"}] * 9},
    }})["trust"]
    assert block["verdict"] == t.UNVERIFIED
    assert block["extra"]["weakest_module"] == "paste"
    assert "pipeline_unmapped_modules:paste" in block["warnings"]
    assert any("unrecognised NAME, not a failed lookup" in r
               for r in block["reasoning"])


def test_pipeline_sub_verdicts_keeps_its_historical_shape() -> None:
    """The named breakdown is additive: existing consumers read `sub_verdicts`
    as a bare list and must not be broken to gain `sub_modules`."""
    env = t.wrap_pipeline({"modules": {
        "ip": {"geolocation": {"found": True}, "rdap": {"found": True},
               "reverse_dns": {"hostname": "a.b"}},
    }})
    assert env["trust"]["extra"]["sub_verdicts"] == [t.VERIFIED]


def test_an_empty_pipeline_says_empty_not_negative() -> None:
    block = t.wrap_pipeline({"modules": {}})["trust"]
    assert block["extra"]["weakest_module"] is None
    assert any("empty, not negative" in r for r in block["reasoning"])
