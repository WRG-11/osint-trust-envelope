"""Tests for cross-scan identity corroboration."""
from __future__ import annotations

from osint_trust_envelope import trust as t


def _scan(username: str, sites: list[str]) -> tuple[str, dict]:
    """Build a minimal envelope for a username with the given found sites."""
    results = [{"status": "found", "site": s} for s in sites]
    env = t.wrap_username_scan({
        "sites_checked": len(sites),
        "sites_found": len(sites),
        "results": results,
    })
    return username, env


def test_disjoint_usernames_produce_no_corroboration():
    envelopes = [
        _scan("alice", ["GitHub", "Twitter", "Reddit", "HN"]),
        _scan("bob", ["YouTube", "TikTok", "Twitch", "Steam"]),
    ]
    result = t.corroborate_identities(envelopes)
    assert result == {}


def test_below_threshold_produces_no_corroboration():
    shared = ["GitHub", "Twitter", "Reddit"]  # 3 < default 5
    envelopes = [
        _scan("alice", shared + ["HN"]),
        _scan("bob", shared + ["Medium"]),
    ]
    result = t.corroborate_identities(envelopes)
    assert result == {}


def test_linked_pair_gets_symmetric_boost():
    shared = ["GitHub", "Twitter", "Reddit", "HN", "Medium", "Stack Overflow"]
    envelopes = [
        _scan("alice", shared),
        _scan("bob", shared + ["Dev.to"]),
    ]
    result = t.corroborate_identities(envelopes)
    assert set(result.keys()) == {"alice", "bob"}
    assert result["alice"]["boost"] == 0.12
    assert result["bob"]["boost"] == 0.12
    # Evidence is bidirectional
    assert result["alice"]["links"][0]["other"] == "bob"
    assert result["bob"]["links"][0]["other"] == "alice"
    assert result["alice"]["links"][0]["shared_count"] == 6


def test_multi_link_boost_caps_at_max():
    shared_ab = ["GitHub", "Twitter", "Reddit", "HN", "Medium"]
    shared_ac = ["GitHub", "Twitter", "Reddit", "HN", "Dev.to"]
    envelopes = [
        _scan("alice", shared_ab + shared_ac),
        _scan("bob", shared_ab),
        _scan("carol", shared_ac),
    ]
    result = t.corroborate_identities(envelopes)
    # alice links with both bob AND carol → two boosts, but capped at 0.20.
    assert result["alice"]["boost"] == 0.20
    assert len(result["alice"]["links"]) == 2


def test_reasoning_bullets_explain_the_link():
    shared = ["GitHub", "Twitter", "Reddit", "HN", "Medium"]
    envelopes = [
        _scan("alice", shared),
        _scan("bob", shared),
    ]
    result = t.corroborate_identities(envelopes)
    assert any("5 platform" in r for r in result["alice"]["reasoning"])
    assert any("'bob'" in r for r in result["alice"]["reasoning"])


def test_not_found_sites_are_ignored():
    """Only 'found' sites count toward the shared set."""
    env_alice = t.wrap_username_scan({
        "sites_checked": 10, "sites_found": 5,
        "results": [
            {"status": "found", "site": s} for s in ["GitHub", "Twitter", "Reddit", "HN", "Medium"]
        ] + [
            {"status": "not_found", "site": s} for s in ["TikTok", "YouTube", "Steam", "Twitch", "Spotify"]
        ],
    })
    env_bob = t.wrap_username_scan({
        "sites_checked": 5, "sites_found": 5,
        "results": [
            {"status": "found", "site": s}
            for s in ["TikTok", "YouTube", "Steam", "Twitch", "Spotify"]
        ],
    })
    # alice's "not_found" sites overlap with bob's "found" sites, but
    # corroboration only counts both-found overlap — zero here.
    result = t.corroborate_identities([("alice", env_alice), ("bob", env_bob)])
    assert result == {}


def test_configurable_threshold():
    shared = ["GitHub", "Twitter", "Reddit"]  # 3 < default 5, but we'll lower
    envelopes = [
        _scan("alice", shared),
        _scan("bob", shared),
    ]
    result = t.corroborate_identities(envelopes, min_shared_platforms=3)
    assert "alice" in result
    assert result["alice"]["links"][0]["shared_count"] == 3
