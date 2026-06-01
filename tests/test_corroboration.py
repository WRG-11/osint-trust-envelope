"""Tests for cross-adapter corroboration + verdict reasoning in
wrap_username_scan."""
from __future__ import annotations

from osint_trust_envelope import trust as t


def _hits(n: int, hc: float | None = None) -> list[dict]:
    """Build n 'found' results, optionally with historical_confidence."""
    return [
        {"status": "found", "site": f"Site{i}", **({"historical_confidence": hc} if hc else {})}
        for i in range(n)
    ]


def test_corroboration_boost_applies_above_three_platforms():
    raw = {"sites_checked": 10, "sites_found": 4, "results": _hits(4) + [{"status": "not_found"}] * 6}
    env = t.wrap_username_scan(raw)
    assert any("corroboration:4_platforms" in w for w in env["trust"]["warnings"])
    # Baseline heuristic conf 0.40 + 0.15 boost = 0.55; the +0.15 also
    # promotes heuristic → inferred on the "significant boost" branch.
    assert env["trust"]["confidence"] >= 0.55
    assert env["trust"]["verdict"] == t.INFERRED
    assert "cross_adapter_corroboration_promotion" in env["trust"]["warnings"]


def test_no_corroboration_when_under_threshold():
    raw = {"sites_checked": 10, "sites_found": 2, "results": _hits(2) + [{"status": "not_found"}] * 8}
    env = t.wrap_username_scan(raw)
    assert not any("corroboration:" in w for w in env["trust"]["warnings"])


def test_email_corroboration_stacks_with_platform_boost():
    raw = {"sites_checked": 10, "sites_found": 4, "results": _hits(4) + [{"status": "not_found"}] * 6}
    env = t.wrap_username_scan(raw, corroborating_email="user@example.com")
    warnings = env["trust"]["warnings"]
    assert any("corroboration:4_platforms" in w for w in warnings)
    assert any("corroboration:email_username_co_occurrence" in w for w in warnings)
    # Stacked boost (0.15 + 0.10 = 0.25, capped) promotes heuristic → inferred.
    assert env["trust"]["verdict"] == t.INFERRED


def test_contradiction_halves_boost_and_raises_warning():
    # 4 hits but all sites have very low historical reliability.
    raw = {
        "sites_checked": 10, "sites_found": 4,
        "results": _hits(4, hc=0.10) + [{"status": "not_found"}] * 6,
    }
    env = t.wrap_username_scan(raw, username="anyone")
    assert any("contradiction:many_hits_low_site_reliability" in w for w in env["trust"]["warnings"])
    # Contradiction blocks the verdict promotion.
    assert env["trust"]["verdict"] == t.HEURISTIC


def test_corroboration_boost_is_capped():
    raw = {"sites_checked": 10, "sites_found": 10, "results": _hits(10)}
    env = t.wrap_username_scan(raw, corroborating_email="a@b.co")
    # Confidence is clamped to ≤1.0 and our max boost is 0.25.
    assert env["trust"]["confidence"] <= 1.0
    # Baseline (0.55) + capped boost (0.25) → around 0.80. Must not exceed 0.85.
    assert env["trust"]["confidence"] <= 0.85


def test_reasoning_present_on_every_branch():
    """Every verdict branch must populate at least one reasoning bullet."""
    # Empty
    env = t.wrap_username_scan({"sites_checked": 0, "sites_found": 0, "results": []})
    assert env["trust"]["reasoning"]
    # Majority errored
    env = t.wrap_username_scan({
        "sites_checked": 10, "sites_found": 0,
        "results": [{"status": "error"}] * 6 + [{"status": "not_found"}] * 4,
    })
    assert env["trust"]["reasoning"]
    # Clean miss
    env = t.wrap_username_scan({
        "sites_checked": 5, "sites_found": 0, "results": [{"status": "not_found"}] * 5,
    })
    assert env["trust"]["reasoning"]
    # Hits
    env = t.wrap_username_scan({"sites_checked": 10, "sites_found": 3, "results": _hits(3) + [{"status": "not_found"}] * 7})
    assert env["trust"]["reasoning"]


def test_reasoning_describes_corroboration_when_applied():
    raw = {"sites_checked": 10, "sites_found": 5, "results": _hits(5) + [{"status": "not_found"}] * 5}
    env = t.wrap_username_scan(raw, corroborating_email="x@y.co")
    joined = " ".join(env["trust"]["reasoning"])
    assert "independent platforms" in joined
    assert "email" in joined.lower()


def test_reasoning_surfaces_parking_rejections():
    raw = {
        "sites_checked": 6, "sites_found": 3,
        "results": _hits(3) + [
            {"status": "not_found", "site": "X", "message": "parking:pattern:for sale"},
            {"status": "not_found", "site": "Y", "message": "parking:title:domain parking"},
            {"status": "not_found", "site": "Z", "message": ""},
        ],
    }
    env = t.wrap_username_scan(raw)
    # parking_rejected counter is exposed + reasoning mentions it.
    assert env["trust"]["extra"]["parking_rejected"] == 2
    joined = " ".join(env["trust"]["reasoning"])
    assert "parking" in joined.lower()


def test_build_trust_exposes_reasoning_field():
    trust = t.build_trust(
        verdict=t.VERIFIED, method="api", source="hibp",
        reasoning=["api returned 200", "hash matched breach db"],
    )
    assert trust["reasoning"] == ["api returned 200", "hash matched breach db"]


def test_build_trust_reasoning_defaults_to_empty_list():
    trust = t.build_trust(verdict=t.VERIFIED, method="api", source="hibp")
    assert trust["reasoning"] == []


def test_anomaly_warning_surfaces_when_detector_flags(monkeypatch):
    """When _detect_site_anomaly returns an anomaly, the trust envelope must
    emit a 'confidence_anomaly' warning + count it in extra."""
    def fake_history(username):
        return {"SiteA": 0.90, "SiteB": 0.50}

    def fake_anomaly(site, conf):
        if site == "SiteA":
            return {"site": site, "confidence": conf, "z_score": 4.2,
                    "is_anomaly": True, "direction": "high",
                    "samples": 20, "mean": 0.55, "std": 0.08}
        return None

    monkeypatch.setattr(t, "_get_site_confidences", fake_history)
    monkeypatch.setattr(t, "_detect_site_anomaly", fake_anomaly)

    raw = {
        "sites_checked": 2, "sites_found": 2,
        "results": [
            {"status": "found", "site": "SiteA"},
            {"status": "found", "site": "SiteB"},
        ],
    }
    env = t.wrap_username_scan(raw, username="some_user")
    assert any("confidence_anomaly" in w for w in env["trust"]["warnings"])
    assert env["trust"]["extra"]["anomalies_detected"] == 1
    # The anomalous site's record carries the anomaly dict inline.
    anomalous = [r for r in env["result"]["results"] if r.get("site") == "SiteA"]
    assert anomalous and anomalous[0].get("anomaly", {}).get("is_anomaly") is True
    # Reasoning explains the anomaly direction.
    assert any("unusually HIGH" in r for r in env["trust"]["reasoning"])


def test_anomaly_silent_when_detector_disabled(monkeypatch):
    """If no anomaly signal is returned, the envelope stays clean."""
    monkeypatch.setattr(t, "_get_site_confidences", lambda u: {"SiteA": 0.55})
    monkeypatch.setattr(t, "_detect_site_anomaly", lambda site, c: None)

    raw = {
        "sites_checked": 1, "sites_found": 1,
        "results": [{"status": "found", "site": "SiteA"}],
    }
    env = t.wrap_username_scan(raw, username="some_user")
    assert not any("confidence_anomaly" in w for w in env["trust"]["warnings"])
    assert env["trust"]["extra"]["anomalies_detected"] == 0
