"""Wrapper-unit tests for the OSINT trust envelope contract.

These pin the verdict ladder, per-wrapper trust policies, and per-source
ceilings so a future refactor cannot silently erode the trust guarantees.
They are transport-independent: HTTP/endpoint-layer tests live alongside the
application that exposes these wrappers, not in this library.
"""
from __future__ import annotations

from osint_trust_envelope import trust as t


# ── Unit tests on the wrappers ──────────────────────────────────────────────
class TestVerdictLadder:
    def test_valid_verdicts_are_exactly_four(self):
        assert t.VALID_VERDICTS == {t.VERIFIED, t.INFERRED, t.HEURISTIC, t.UNVERIFIED}

    def test_confidence_anchors_are_ordered(self):
        ca = {
            v: t._CONF_ANCHOR[v]
            for v in (t.VERIFIED, t.INFERRED, t.HEURISTIC, t.UNVERIFIED)
        }
        values = list(ca.values())
        assert values == sorted(values, reverse=True), "confidence anchors must be descending"

    def test_build_trust_clamps_confidence(self):
        tb = t.build_trust(verdict=t.VERIFIED, method="x", source="y", confidence=1.7)
        assert tb["confidence"] == 1.0
        tb = t.build_trust(verdict=t.VERIFIED, method="x", source="y", confidence=-0.3)
        assert tb["confidence"] == 0.0

    def test_build_trust_invalid_verdict_becomes_unverified(self):
        tb = t.build_trust(verdict="nonsense", method="x", source="y")
        assert tb["verdict"] == t.UNVERIFIED

    def test_envelope_preserves_raw_result(self):
        raw = {"foo": "bar", "nested": {"k": 1}}
        env = t.envelope(raw, t.build_trust(verdict=t.VERIFIED, method="m", source="s"))
        assert env["result"] == raw
        assert env["trust"]["verdict"] == t.VERIFIED


class TestUsernameScanWrapper:
    def test_signature_accepts_username_and_strict_kwargs(self):
        """The wrapper must remain backwards-compatible (positional raw)
        but also accept the new keyword arguments."""
        env = t.wrap_username_scan(
            {"sites_checked": 1, "sites_found": 0, "results": [{"status": "not_found", "site": "x"}]},
            username="someone",
            strict=True,
        )
        assert "trust" in env
        assert env["trust"]["extra"]["strict_mode"] is True

    def test_no_sites_checked_is_unverified(self):
        env = t.wrap_username_scan({"sites_checked": 0, "sites_found": 0, "results": []})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert "no_sites_checked" in env["trust"]["warnings"]

    def test_majority_errored_is_unverified(self):
        results = [{"status": "error"}] * 6 + [{"status": "found"}] * 4
        env = t.wrap_username_scan(
            {"sites_checked": 10, "sites_found": 4, "results": results}
        )
        assert env["trust"]["verdict"] == t.UNVERIFIED

    def test_found_sites_are_heuristic_not_verified(self):
        """404-based detection is fundamentally fragile; never verified.

        Below the cross-adapter corroboration threshold (3+ independent
        platforms) the verdict stays at HEURISTIC with conf ≤ 0.55. The
        corroboration promotion path is covered separately in
        test_corroboration.
        """
        env = t.wrap_username_scan({
            "sites_checked": 10,
            "sites_found": 2,
            "results": [{"status": "found"}] * 2 + [{"status": "not_found"}] * 8,
        })
        assert env["trust"]["verdict"] == t.HEURISTIC
        # confidence capped at 0.55 without corroboration boost
        assert env["trust"]["confidence"] <= 0.55
        assert "http_status_based_detection" in env["trust"]["warnings"]
        assert "verify_hits_manually" in env["trust"]["warnings"]

    def test_no_hits_but_sites_responded_is_inferred(self):
        env = t.wrap_username_scan({
            "sites_checked": 10,
            "sites_found": 0,
            "results": [{"status": "not_found"}] * 10,
        })
        assert env["trust"]["verdict"] == t.INFERRED

    def test_adapter_error_convention_sites_checked_zero(self):
        """Canonical pattern for 'scanner could not run' (timeout, binary missing).

        Pass sites_checked=0 with an empty results list. This is distinct from
        a clean-negative (sites_found=0 but sites DID respond), which yields
        inferred. The zero-checked convention yields unverified -- the honest
        'we have no data' state.
        """
        env = t.wrap_username_scan({"sites_checked": 0, "sites_found": 0, "results": []})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert "no_sites_checked" in env["trust"]["warnings"]

    def test_extra_includes_site_counts(self):
        env = t.wrap_username_scan({
            "sites_checked": 10,
            "sites_found": 3,
            "results": [
                {"status": "found"}, {"status": "found"}, {"status": "found"},
                {"status": "error"}, {"status": "error"},
            ] + [{"status": "not_found"}] * 5,
        })
        extra = env["trust"]["extra"]
        assert extra["sites_checked"] == 10
        assert extra["sites_found"] == 3
        assert extra["sites_errored"] == 2


class TestUsernameScanConfidenceEnrichment:
    """Tests for the per-site confidence integration hook in wrap_username_scan.

    We monkeypatch ``_get_site_confidences`` so these tests are hermetic and
    do not require any external history provider.
    """

    def test_no_username_means_no_history_lookup(self, monkeypatch):
        called = []
        monkeypatch.setattr(
            t, "_get_site_confidences",
            lambda u: (called.append(u), {})[1],
        )
        env = t.wrap_username_scan({
            "sites_checked": 3,
            "sites_found": 1,
            "results": [{"status": "found", "site": "GitHub"}] + [{"status": "not_found", "site": "x"}] * 2,
        })
        # No username passed → hook must not be consulted.
        assert called == []
        assert env["trust"]["extra"]["history_sites_known"] == 0

    def test_history_annotates_each_result(self, monkeypatch):
        monkeypatch.setattr(
            t, "_get_site_confidences",
            lambda u: {"GitHub": 0.92, "Reddit": 0.55, "Obscure": 0.12},
        )
        env = t.wrap_username_scan(
            {
                "sites_checked": 3,
                "sites_found": 3,
                "results": [
                    {"status": "found", "site": "GitHub"},
                    {"status": "found", "site": "Reddit"},
                    {"status": "found", "site": "Obscure"},
                ],
            },
            username="jdoe",
        )
        results = env["result"]["results"]
        sites = {r["site"]: r for r in results}
        assert sites["GitHub"]["historical_confidence"] == 0.92
        assert sites["Reddit"]["historical_confidence"] == 0.55
        assert sites["Obscure"]["historical_confidence"] == 0.12
        assert env["trust"]["extra"]["history_sites_known"] == 3

    def test_high_history_upgrades_verdict_to_inferred(self, monkeypatch):
        """When ALL found sites have historical confidence >= 0.70 the
        wrapper upgrades from heuristic to inferred."""
        monkeypatch.setattr(
            t, "_get_site_confidences",
            lambda u: {"GitHub": 0.92, "Twitter": 0.85},
        )
        env = t.wrap_username_scan(
            {
                "sites_checked": 2,
                "sites_found": 2,
                "results": [
                    {"status": "found", "site": "GitHub"},
                    {"status": "found", "site": "Twitter"},
                ],
            },
            username="jdoe",
        )
        assert env["trust"]["verdict"] == t.INFERRED
        assert "history_backed_inference" in env["trust"]["warnings"]
        # Still capped below 0.80 — we never claim verified from scraping.
        assert env["trust"]["confidence"] < 0.80

    def test_low_history_does_not_upgrade(self, monkeypatch):
        monkeypatch.setattr(
            t, "_get_site_confidences",
            lambda u: {"SketchySite": 0.15},
        )
        env = t.wrap_username_scan(
            {
                "sites_checked": 1,
                "sites_found": 1,
                "results": [{"status": "found", "site": "SketchySite"}],
            },
            username="jdoe",
        )
        # A single low-confidence hit must NOT escape heuristic.
        assert env["trust"]["verdict"] == t.HEURISTIC

    def test_strict_mode_drops_low_confidence_hits(self, monkeypatch):
        monkeypatch.setattr(
            t, "_get_site_confidences",
            lambda u: {"GitHub": 0.90, "SketchySite": 0.15, "OkSite": 0.65},
        )
        env = t.wrap_username_scan(
            {
                "sites_checked": 3,
                "sites_found": 3,
                "results": [
                    {"status": "found", "site": "GitHub"},
                    {"status": "found", "site": "SketchySite"},
                    {"status": "found", "site": "OkSite"},
                ],
            },
            username="jdoe",
            strict=True,
        )
        surviving = {r["site"] for r in env["result"]["results"] if r.get("status") == "found"}
        # SketchySite (0.15 < 0.60) is dropped, the rest survive.
        assert surviving == {"GitHub", "OkSite"}
        assert env["trust"]["extra"]["filtered_low_confidence"] == 1
        assert env["trust"]["extra"]["strict_mode"] is True
        assert "strict_mode_active" in env["trust"]["warnings"]

    def test_strict_mode_without_history_is_noop(self, monkeypatch):
        """If there is no history data, strict mode cannot filter anything
        and must fall through gracefully without erasing hits."""
        monkeypatch.setattr(t, "_get_site_confidences", lambda u: {})
        env = t.wrap_username_scan(
            {
                "sites_checked": 2,
                "sites_found": 2,
                "results": [
                    {"status": "found", "site": "A"},
                    {"status": "found", "site": "B"},
                ],
            },
            username="jdoe",
            strict=True,
        )
        surviving = {r["site"] for r in env["result"]["results"] if r.get("status") == "found"}
        assert surviving == {"A", "B"}
        assert env["trust"]["extra"]["filtered_low_confidence"] == 0

    def test_get_site_confidences_empty_on_blank_username(self):
        assert t._get_site_confidences("") == {}
        assert t._get_site_confidences(None) == {}  # type: ignore[arg-type]  # intentional None input — verifies empty-dict fallback


class TestPhoneWrapper:
    def test_phone_regex_only_is_heuristic(self):
        """Without libphonenumber and without messenger hits the verdict
        must stay at heuristic with confidence below 0.60."""
        env = t.wrap_phone({
            "parsed": {
                "valid": True,
                "country_code": "+90",
                "line_type": "mobile",
                "enrichment_source": "regex",
            },
        })
        assert env["trust"]["verdict"] == t.HEURISTIC
        assert env["trust"]["confidence"] < 0.60

    def test_phone_libphonenumber_only_still_heuristic(self):
        """libphonenumber alone bumps confidence but does NOT escape heuristic
        because portability still applies."""
        env = t.wrap_phone({
            "parsed": {
                "valid": True,
                "country_code": "+90",
                "line_type": "mobile",
                "enrichment_source": "libphonenumber",
            },
        })
        assert env["trust"]["verdict"] == t.HEURISTIC
        assert 0.50 <= env["trust"]["confidence"] <= 0.65
        assert env["trust"]["extra"]["enrichment_source"] == "libphonenumber"

    def test_phone_with_one_messenger_hit_becomes_inferred(self):
        env = t.wrap_phone({
            "parsed": {
                "valid": True,
                "country_code": "+90",
                "line_type": "mobile",
                "enrichment_source": "libphonenumber",
            },
            "social_checks": [
                {"platform": "WhatsApp", "possible": True},
                {"platform": "Telegram", "possible": False},
            ],
        })
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["extra"]["messenger_hits"] == 1
        assert env["trust"]["confidence"] >= 0.66

    def test_phone_with_two_messenger_hits_higher_confidence(self):
        env = t.wrap_phone({
            "parsed": {
                "valid": True,
                "country_code": "+90",
                "enrichment_source": "libphonenumber",
            },
            "social_checks": [
                {"platform": "WhatsApp", "possible": True},
                {"platform": "Telegram", "possible": True},
            ],
        })
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["extra"]["messenger_hits"] == 2
        assert env["trust"]["confidence"] >= 0.74

    def test_phone_with_numverify_confirmation_caps_below_verified(self):
        """A reverse-lookup is the strongest signal we have but the verdict
        still stays at inferred because the carrier can be stale."""
        env = t.wrap_phone({
            "parsed": {
                "valid": True,
                "country_code": "+90",
                "enrichment_source": "libphonenumber",
            },
            "social_checks": [],
            "reverse_lookup": {
                "lookup_done": True,
                "carrier": "Example Carrier",
                "source": "numverify",
            },
        })
        assert env["trust"]["verdict"] == t.INFERRED
        # Capped: even a reverse-lookup cannot make us claim verified.
        assert env["trust"]["confidence"] < 0.85
        assert env["trust"]["extra"]["numverify_used"] is True

    def test_phone_never_exceeds_inferred_even_with_everything(self):
        """The verdict ladder for phone has a hard ceiling at inferred."""
        env = t.wrap_phone({
            "parsed": {
                "valid": True,
                "country_code": "+90",
                "enrichment_source": "libphonenumber",
            },
            "social_checks": [
                {"platform": "WhatsApp", "possible": True},
                {"platform": "Telegram", "possible": True},
            ],
            "reverse_lookup": {"lookup_done": True, "carrier": "Example Carrier"},
        })
        # The strongest possible state is inferred, never verified.
        assert env["trust"]["verdict"] in {t.INFERRED, t.HEURISTIC}
        assert env["trust"]["verdict"] != t.VERIFIED

    def test_phone_invalid_format_is_unverified(self):
        env = t.wrap_phone({"parsed": {"valid": False}})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert "invalid_phone_format" in env["trust"]["errors"]

    def test_phone_always_has_mnp_disclaimer(self):
        """The number portability caveat is non-negotiable on every valid
        phone result, regardless of how rich the data is."""
        for parsed_kwargs in (
            {"valid": True, "country_code": "+90", "enrichment_source": "regex"},
            {"valid": True, "country_code": "+1", "enrichment_source": "libphonenumber"},
        ):
            env = t.wrap_phone({"parsed": parsed_kwargs})
            warns = env["trust"]["warnings"]
            assert "number_portability_not_reflected" in warns
            assert "ownership_not_determinable_from_number_alone" in warns

    def test_phone_warns_when_only_regex_fallback_used(self):
        env = t.wrap_phone({
            "parsed": {"valid": True, "country_code": "+90", "enrichment_source": "regex"},
        })
        warns = env["trust"]["warnings"]
        assert "install_phonenumbers_for_better_data" in warns


class TestEmailWrapper:
    """Email tier-2 ladder pin: heuristic 0.30 → 0.40 → 0.50 → inferred 0.60 → 0.70 → 0.78 → 0.84.
    Hard cap: never reaches verified (mailbox existence cannot be proven).
    """

    # ── Format / floor ────────────────────────────────────────────────────
    def test_invalid_format_is_unverified(self):
        env = t.wrap_email({"validation": {"format_valid": False}, "services_found": 0})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert "invalid_email_format" in env["trust"]["errors"]

    def test_mx_unreachable_is_heuristic(self):
        env = t.wrap_email({
            "validation": {"format_valid": True, "mx_reachable": False},
            "services_found": 0,
        })
        assert env["trust"]["verdict"] == t.HEURISTIC
        assert "mx_lookup_failed_or_unreachable" in env["trust"]["warnings"]

    # ── Climbing the ladder ──────────────────────────────────────────────
    def test_mx_only_is_heuristic_040(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_records": [{"priority": 10, "exchange": "mx.example.com"}],
            },
        })
        assert env["trust"]["verdict"] == t.HEURISTIC
        assert env["trust"]["confidence"] == 0.40

    def test_mx_with_classified_provider_is_heuristic_050(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_records": [{"priority": 1, "exchange": "aspmx.l.google.com"}],
                "mx_provider": "Google Workspace",
            },
        })
        assert env["trust"]["verdict"] == t.HEURISTIC
        assert env["trust"]["confidence"] == 0.50

    def test_mx_with_dmarc_none_is_inferred_060(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_provider": "Google Workspace",
                "dmarc": {"present": True, "policy": "none"},
            },
        })
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["confidence"] == 0.60
        assert "dmarc_policy_none_no_enforcement" in env["trust"]["warnings"]

    def test_mx_with_dmarc_reject_is_inferred_070(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_provider": "Microsoft 365",
                "dmarc": {"present": True, "policy": "reject"},
            },
        })
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["confidence"] == 0.70

    def test_dmarc_strict_plus_services_hits_078(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_provider": "Google Workspace",
                "dmarc": {"present": True, "policy": "quarantine"},
                "role_account": {"is_role": True, "matched": "info"},
            },
            "services_found": 2,
        })
        assert env["trust"]["verdict"] == t.INFERRED
        # role account blocks the 0.84 step, services pump us to 0.78
        assert env["trust"]["confidence"] == 0.78

    def test_full_chain_personal_mailbox_caps_at_084(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_records": [{"priority": 1, "exchange": "aspmx.l.google.com"}],
                "mx_provider": "Google Workspace",
                "spf": {"present": True, "all_qualifier": "-"},
                "dmarc": {"present": True, "policy": "reject"},
                "disposable": False,
                "role_account": {"is_role": False, "matched": None},
            },
            "services_found": 3,
        })
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["confidence"] == 0.84

    def test_email_never_exceeds_inferred_even_with_everything(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_records": [{"priority": 1, "exchange": "aspmx.l.google.com"}],
                "mx_provider": "Google Workspace",
                "spf": {"present": True, "all_qualifier": "-"},
                "dmarc": {"present": True, "policy": "reject"},
                "disposable": False,
                "role_account": {"is_role": False, "matched": None},
            },
            "services_found": 99,
            "breach_summary": {"breach_count": 5},
        })
        assert env["trust"]["verdict"] != t.VERIFIED
        assert env["trust"]["confidence"] < 0.90

    # ── Mandatory disclaimers + flags ────────────────────────────────────
    def test_email_always_has_mailbox_disclaimers(self):
        env = t.wrap_email({
            "validation": {"format_valid": True, "mx_reachable": True},
        })
        warns = env["trust"]["warnings"]
        assert "mailbox_existence_not_proven" in warns
        assert "aliases_and_forwarders_invisible" in warns

    def test_disposable_provider_warning(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "disposable": True,
                "mx_provider": "self-hosted or unknown provider",
                "dmarc": {"present": True, "policy": "reject"},
            },
        })
        assert "disposable_provider" in env["trust"]["warnings"]
        # disposable blocks the 0.84 cap step
        assert env["trust"]["confidence"] <= 0.78

    def test_role_account_warning(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "role_account": {"is_role": True, "matched": "info"},
            },
        })
        warns = env["trust"]["warnings"]
        assert any(w.startswith("role_account:") for w in warns)

    def test_no_dmarc_warning(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "dmarc": {"present": False},
            },
        })
        assert "no_dmarc_record" in env["trust"]["warnings"]

    def test_extra_block_exposes_tier2_fields(self):
        env = t.wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_records": [{"priority": 1, "exchange": "mx.example.com"}],
                "mx_provider": "self-hosted or unknown provider",
                "dmarc": {"present": True, "policy": "quarantine"},
                "spf": {"present": True, "all_qualifier": "~"},
            },
        })
        extra = env["trust"]["extra"]
        assert extra["mx_provider"] == "self-hosted or unknown provider"
        assert extra["mx_count"] == 1
        assert extra["spf_present"] is True
        assert extra["dmarc_present"] is True
        assert extra["dmarc_policy"] == "quarantine"


class TestIpWrapper:
    def test_all_sources_found_is_verified_high_confidence(self):
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "a.b.c"},
        })
        assert env["trust"]["verdict"] == t.VERIFIED
        assert env["trust"]["confidence"] >= 0.90

    def test_two_of_three_is_verified_lower_confidence(self):
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {},
        })
        assert env["trust"]["verdict"] == t.VERIFIED
        assert 0.75 <= env["trust"]["confidence"] < 0.90

    def test_all_failed_is_unverified(self):
        env = t.wrap_ip({"geolocation": {}, "rdap": {}, "reverse_dns": {}})
        assert env["trust"]["verdict"] == t.UNVERIFIED

    def test_private_ip_gets_warning(self):
        env = t.wrap_ip({
            "ip_type": "private",
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "router.local"},
        })
        assert "private_ip_no_public_intel" in env["trust"]["warnings"]

    # ── Tier-2 ──────────────────────────────────────────────────────────

    def test_tor_exit_promotes_to_verified_and_caps_at_095(self):
        # Even if only 1 of 3 base sources, tor exit promotes to verified.
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {},
            "reverse_dns": {},
            "tor": {"is_tor": True, "list_size": 1234, "source": "check.torproject.org"},
        })
        assert env["trust"]["verdict"] == t.VERIFIED
        assert env["trust"]["confidence"] == 0.95
        assert "tor_exit_node" in env["trust"]["warnings"]
        assert env["trust"]["extra"]["is_tor"] is True

    def test_tor_negative_no_warning(self):
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "x.y"},
            "tor": {"is_tor": False, "list_size": 1234},
        })
        assert "tor_exit_node" not in env["trust"]["warnings"]
        assert env["trust"]["extra"]["is_tor"] is False

    def test_dnsbl_listed_adds_per_blacklist_warning(self):
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "x.y"},
            "dnsbl": {
                "checked": True,
                "listed": True,
                "hits": [
                    {"name": "Spamhaus ZEN", "host": "zen.spamhaus.org"},
                    {"name": "SORBS", "host": "dnsbl.sorbs.net"},
                ],
            },
        })
        warns = env["trust"]["warnings"]
        assert "dnsbl_listed:Spamhaus ZEN" in warns
        assert "dnsbl_listed:SORBS" in warns
        assert env["trust"]["extra"]["is_dnsbl_listed"] is True
        assert env["trust"]["extra"]["dnsbl_hits"] == ["Spamhaus ZEN", "SORBS"]

    def test_dnsbl_clean_no_warnings(self):
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "x.y"},
            "dnsbl": {"checked": True, "listed": False, "hits": []},
        })
        assert env["trust"]["extra"]["is_dnsbl_listed"] is False
        for w in env["trust"]["warnings"]:
            assert not w.startswith("dnsbl_listed:")

    def test_cloud_provider_attaches_warnings(self):
        env = t.wrap_ip({
            "geolocation": {"found": True, "isp": "Amazon.com, Inc.", "org": "AWS"},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "ec2.amazonaws.com"},
            "asn_classification": {"class": "cloud", "label": "AWS", "match": "amazon"},
        })
        warns = env["trust"]["warnings"]
        assert "cloud_provider:AWS" in warns
        assert "datacenter_ip_no_human" in warns
        assert env["trust"]["extra"]["asn_class"] == "cloud"
        assert env["trust"]["extra"]["is_cloud_provider"] is True
        assert env["trust"]["extra"]["is_datacenter"] is True

    def test_hosting_class_warns_datacenter_only(self):
        env = t.wrap_ip({
            "geolocation": {"found": True, "isp": "Some Hosting"},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "srv.example.net"},
            "asn_classification": {"class": "hosting", "label": "hosting/datacenter", "match": None},
        })
        warns = env["trust"]["warnings"]
        assert "datacenter_ip_no_human" in warns
        assert not any(w.startswith("cloud_provider:") for w in warns)
        assert env["trust"]["extra"]["is_datacenter"] is True
        assert env["trust"]["extra"]["is_cloud_provider"] is False

    def test_mobile_class_warns_dynamic(self):
        env = t.wrap_ip({
            "geolocation": {"found": True, "isp": "Turkcell Mobile"},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "mob.tcell.tr"},
            "asn_classification": {"class": "mobile", "label": "mobile carrier", "match": None},
        })
        assert "mobile_carrier_ip_dynamic_assignment" in env["trust"]["warnings"]
        assert env["trust"]["extra"]["asn_class"] == "mobile"
        assert env["trust"]["extra"]["is_datacenter"] is False

    def test_residential_class_no_extra_warning(self):
        env = t.wrap_ip({
            "geolocation": {"found": True, "isp": "TTNET"},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "host.ttnet.tr"},
            "asn_classification": {"class": "residential", "label": "residential ISP", "match": None},
        })
        warns = env["trust"]["warnings"]
        assert "datacenter_ip_no_human" not in warns
        assert "mobile_carrier_ip_dynamic_assignment" not in warns
        assert env["trust"]["extra"]["asn_class"] == "residential"

    def test_mandatory_geolocation_disclaimer_always_present(self):
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "h"},
        })
        assert "ip_geolocation_is_isp_level_not_user_level" in env["trust"]["warnings"]

    def test_extra_block_exposes_tier2_fields(self):
        env = t.wrap_ip({
            "geolocation": {"found": True},
            "rdap": {"found": True},
            "reverse_dns": {"hostname": "h"},
            "tor": {"is_tor": False, "list_size": 9000},
            "dnsbl": {"checked": True, "listed": False, "hits": []},
            "asn_classification": {"class": "cloud", "label": "Cloudflare", "match": "cloudflare"},
        })
        extra = env["trust"]["extra"]
        for key in (
            "is_tor", "tor_list_size", "is_dnsbl_listed", "dnsbl_hits",
            "dnsbl_checked", "asn_class", "asn_label", "is_cloud_provider",
            "is_datacenter", "geolocation_found", "rdap_found",
            "reverse_dns_found", "ip_type",
        ):
            assert key in extra, f"missing extra field: {key}"


class TestDomainWrapper:
    def test_all_four_sources_verified(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
        })
        assert env["trust"]["verdict"] == t.VERIFIED
        assert env["trust"]["confidence"] >= 0.90

    def test_none_reachable_is_unverified(self):
        env = t.wrap_domain({"dns": {}, "rdap": {}, "ssl": {}, "http": {}})
        assert env["trust"]["verdict"] == t.UNVERIFIED

    def test_rdap_only_is_inferred(self):
        """Only RDAP responded (e.g. domain-age lookup with no DNS/SSL/HTTP check).

        One of four authoritative sources is enough for inferred, not verified.
        This is the typical input from a keyless RDAP-only lookup.
        """
        env = t.wrap_domain({
            "rdap": {"found": True},
            "dns": {},
            "ssl": {"has_ssl": False},
            "http": {"reachable": False},
        })
        assert env["trust"]["verdict"] == t.INFERRED
        assert 0.50 <= env["trust"]["confidence"] <= 0.80
        assert "only_one_source_responded" in env["trust"]["warnings"]

    # ── Tier-2 ──────────────────────────────────────────────────────────

    def test_dnssec_validated_boosts_confidence(self):
        # Same base case but with DNSSEC validated → +0.02
        base = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
        })
        boosted = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "dnssec": {"checked": True, "validated": True,
                       "ad_flag": True, "ds_present": True},
        })
        assert boosted["trust"]["confidence"] > base["trust"]["confidence"]
        assert boosted["trust"]["extra"]["dnssec_validated"] is True

    def test_ct_logs_boost_and_warning(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "ct_logs": {"checked": True, "count": 12, "cert_count": 25,
                        "names": ["a.example.com"] * 12},
        })
        assert env["trust"]["extra"]["ct_log_count"] == 12
        warns = env["trust"]["warnings"]
        assert any(w == "ct_revealed_12_subdomains" for w in warns)

    def test_ct_unavailable_warning(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "ct_logs": {"checked": False, "count": 0,
                        "skipped_reason": "crtsh_unavailable_status_503"},
        })
        warns = env["trust"]["warnings"]
        assert any(w.startswith("ct_log_unavailable:") for w in warns)

    def test_dnssec_checked_but_not_validated_warns(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "dnssec": {"checked": True, "validated": False,
                       "ad_flag": False, "ds_present": False},
        })
        assert "no_dnssec_validation" in env["trust"]["warnings"]

    def test_no_spf_warning_when_absent(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "email_auth": {"spf": {"present": False}, "dmarc": {"present": True, "policy": "reject"}},
        })
        warns = env["trust"]["warnings"]
        assert "no_spf_record" in warns
        assert "no_dmarc_record" not in warns

    def test_dmarc_policy_none_warns(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "email_auth": {"spf": {"present": True}, "dmarc": {"present": True, "policy": "none"}},
        })
        warns = env["trust"]["warnings"]
        assert "dmarc_policy_none_no_enforcement" in warns

    def test_mandatory_registrar_disclaimer_always_present(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
        })
        assert "registrar_data_may_be_privacy_redacted" in env["trust"]["warnings"]

    def test_confidence_capped_at_096(self):
        # Base verified + DNSSEC + CT should still cap at 0.96
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "dnssec": {"checked": True, "validated": True,
                       "ad_flag": True, "ds_present": True},
            "ct_logs": {"checked": True, "count": 50,
                        "names": ["x"] * 50},
        })
        assert env["trust"]["confidence"] <= 0.96

    def test_extra_block_exposes_tier2_fields(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
            "dnssec": {"checked": True, "validated": True},
            "email_auth": {"spf": {"present": True}, "dmarc": {"present": True, "policy": "reject"}},
            "ct_logs": {"checked": True, "count": 5, "cert_count": 9},
            "ct_alive": {"alive": [{"subdomain": "a", "ips": ["1"]}]},
        })
        extra = env["trust"]["extra"]
        for key in (
            "dnssec_validated", "dnssec_checked", "spf_present",
            "dmarc_present", "dmarc_policy", "ct_log_count",
            "ct_log_cert_count", "ct_alive_count", "ct_log_checked",
        ):
            assert key in extra, f"missing extra: {key}"

    # ── Tier-2 SSL deep inspection ─────────────────────────────────────

    def test_ssl_deep_healthy_boosts_confidence(self):
        base = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
        })
        boosted = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "protocol_class": "modern",
                "cipher_class": "strong",
                "san_match": True,
                "is_self_signed": False,
                "expiry_status": "ok",
                "days_to_expiry": 90,
            },
            "http": {"reachable": True},
        })
        assert boosted["trust"]["confidence"] > base["trust"]["confidence"]
        assert boosted["trust"]["extra"]["ssl_deep_healthy"] is True

    def test_ssl_expired_warning(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "expiry_status": "expired",
                "days_to_expiry": -3,
                "protocol_class": "modern",
                "cipher_class": "strong",
                "san_match": True,
                "is_self_signed": False,
            },
            "http": {"reachable": True},
        })
        assert "ssl_certificate_expired" in env["trust"]["warnings"]
        assert env["trust"]["extra"]["ssl_deep_healthy"] is False

    def test_ssl_critical_expiry_warning_includes_days(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "expiry_status": "critical",
                "days_to_expiry": 5,
                "protocol_class": "modern",
                "cipher_class": "strong",
                "san_match": True,
                "is_self_signed": False,
            },
            "http": {"reachable": True},
        })
        assert "ssl_expires_in_5_days" in env["trust"]["warnings"]

    def test_ssl_insecure_protocol_warning(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "protocol_class": "insecure",
                "cipher_class": "strong",
                "san_match": True,
                "is_self_signed": False,
                "expiry_status": "ok",
                "days_to_expiry": 90,
            },
            "http": {"reachable": True},
        })
        assert "tls_insecure_protocol" in env["trust"]["warnings"]

    def test_ssl_legacy_protocol_warns_softly(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "protocol_class": "legacy",
                "cipher_class": "strong",
                "san_match": True,
                "is_self_signed": False,
                "expiry_status": "ok",
                "days_to_expiry": 90,
            },
            "http": {"reachable": True},
        })
        assert "tls_legacy_protocol_consider_upgrade" in env["trust"]["warnings"]

    def test_ssl_weak_cipher_warning(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "protocol_class": "modern",
                "cipher_class": "weak",
                "san_match": True,
                "is_self_signed": False,
                "expiry_status": "ok",
                "days_to_expiry": 90,
            },
            "http": {"reachable": True},
        })
        assert "tls_weak_cipher" in env["trust"]["warnings"]

    def test_ssl_san_mismatch_warning(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "protocol_class": "modern",
                "cipher_class": "strong",
                "san_match": False,
                "is_self_signed": False,
                "expiry_status": "ok",
                "days_to_expiry": 90,
            },
            "http": {"reachable": True},
        })
        assert "ssl_san_mismatch_host_not_in_certificate" in env["trust"]["warnings"]

    def test_ssl_self_signed_warning(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "protocol_class": "modern",
                "cipher_class": "strong",
                "san_match": True,
                "is_self_signed": True,
                "expiry_status": "ok",
                "days_to_expiry": 90,
            },
            "http": {"reachable": True},
        })
        assert "ssl_self_signed_certificate" in env["trust"]["warnings"]

    def test_ssl_deep_no_warnings_when_ssl_absent(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": False},
            "http": {"reachable": True},
        })
        warns = env["trust"]["warnings"]
        assert "ssl_certificate_expired" not in warns
        assert "tls_insecure_protocol" not in warns
        assert "tls_weak_cipher" not in warns
        assert "ssl_san_mismatch_host_not_in_certificate" not in warns
        assert "ssl_self_signed_certificate" not in warns

    def test_extra_block_exposes_ssl_deep_fields(self):
        env = t.wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {
                "has_ssl": True,
                "protocol": "TLSv1.3",
                "protocol_class": "modern",
                "cipher_name": "TLS_AES_256_GCM_SHA384",
                "cipher_bits": 256,
                "cipher_class": "strong",
                "expiry_status": "ok",
                "days_to_expiry": 60,
                "san_match": True,
                "is_self_signed": False,
                "sha256_fingerprint": "AB:CD:EF",
            },
            "http": {"reachable": True},
        })
        extra = env["trust"]["extra"]
        for key in (
            "ssl_protocol", "ssl_protocol_class", "ssl_cipher_name",
            "ssl_cipher_bits", "ssl_cipher_class", "ssl_expiry_status",
            "ssl_days_to_expiry", "ssl_san_match", "ssl_self_signed",
            "ssl_sha256_fingerprint", "ssl_deep_healthy",
        ):
            assert key in extra, f"missing extra: {key}"
        assert extra["ssl_sha256_fingerprint"] == "AB:CD:EF"
        assert extra["ssl_deep_healthy"] is True


class TestBreachWrapper:
    def test_password_checked_is_verified(self):
        env = t.wrap_breach({
            "password_check": {"checked": True, "breached": False},
            "email_check": None,
        })
        assert env["trust"]["verdict"] == t.VERIFIED

    def test_password_ok_email_skipped_warns_about_hibp(self):
        env = t.wrap_breach({
            "password_check": {"checked": True},
            "email_check": {"skipped": True},
        })
        assert env["trust"]["verdict"] == t.VERIFIED
        assert "email_breach_skipped_no_hibp_key" in env["trust"]["warnings"]

    def test_all_failed_is_unverified(self):
        env = t.wrap_breach({
            "password_check": {"checked": False, "error": "network"},
            "email_check": {"checked": False, "error": "timeout"},
        })
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert len(env["trust"]["errors"]) >= 1


class TestPipelineWrapper:
    def test_pipeline_verdict_equals_weakest_submodule(self):
        """A pipeline is only as trustworthy as its weakest link."""
        env = t.wrap_pipeline({
            "modules": {
                "ip": {  # would be verified
                    "geolocation": {"found": True},
                    "rdap": {"found": True},
                    "reverse_dns": {"hostname": "a.b"},
                },
                "phone": {"parsed": {"valid": True}},  # always heuristic
            },
        })
        # weakest = heuristic
        assert env["trust"]["verdict"] == t.HEURISTIC

    def test_empty_pipeline_is_unverified(self):
        env = t.wrap_pipeline({"modules": {}})
        assert env["trust"]["verdict"] == t.UNVERIFIED

    def test_pipeline_exposes_sub_verdicts(self):
        env = t.wrap_pipeline({
            "modules": {
                "ip": {
                    "geolocation": {"found": True},
                    "rdap": {"found": True},
                    "reverse_dns": {"hostname": "a.b"},
                },
            },
        })
        assert env["trust"]["extra"]["sub_verdicts"] == [t.VERIFIED]


class TestNameWrapper:
    def test_name_is_heuristic_generator(self):
        env = t.wrap_name({"username_candidates": ["jdoe", "john.doe"]})
        assert env["trust"]["verdict"] == t.HEURISTIC
        assert "feed_to_username_scan_for_verification" in env["trust"]["warnings"]
