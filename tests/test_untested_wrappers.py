"""Wrapper-unit tests for the seven wrap_* functions that previously had
ZERO direct test coverage: wrap_avatar, wrap_company, wrap_whois, wrap_ssl,
wrap_paste, wrap_metadata, wrap_generic.

Found via a live coverage measurement (79% actual vs the .coveragerc
fail_under=80 floor) — these seven functions are exactly why the number sat
below the declared floor. Same style/rigor as test_trust_wrappers.py: pin
the verdict ladder and per-wrapper trust policy so a future refactor can't
silently erode it.
"""
from __future__ import annotations

from osint_trust_envelope import trust as t


class TestAvatarWrapper:
    def test_found_in_results_list_is_inferred(self):
        env = t.wrap_avatar({"results": [{"platform": "Gravatar", "found": True}]})
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["confidence"] == 0.65
        assert env["trust"]["extra"]["any_found"] is True

    def test_platforms_key_is_an_accepted_alias_for_results(self):
        env = t.wrap_avatar({"platforms": [{"platform": "unavatar", "found": True}]})
        assert env["trust"]["verdict"] == t.INFERRED

    def test_no_hits_is_unverified(self):
        env = t.wrap_avatar({"results": [{"platform": "Gravatar", "found": False}]})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert env["trust"]["confidence"] == 0.20
        assert "no_avatars_matched" in env["trust"]["warnings"]

    def test_non_list_results_falls_back_to_top_level_found_flag(self):
        """When 'results' isn't a list (unexpected adapter shape), the
        wrapper falls back to a bare top-level found/gravatar_found flag
        instead of crashing."""
        env = t.wrap_avatar({"results": {"unexpected": "shape"}, "gravatar_found": True})
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["extra"]["any_found"] is True

    def test_always_carries_ownership_disclaimer(self):
        env = t.wrap_avatar({"results": []})
        warns = env["trust"]["warnings"]
        assert "profile_image_existence_not_ownership" in warns
        assert "avatar_correlation_is_probabilistic" in warns

    def test_never_exceeds_inferred(self):
        env = t.wrap_avatar({"results": [{"found": True}] * 10})
        assert env["trust"]["verdict"] != t.VERIFIED

    def test_non_dict_input_does_not_crash(self):
        env = t.wrap_avatar(None)  # type: ignore[arg-type]
        assert env["trust"]["verdict"] == t.UNVERIFIED


class TestCompanyWrapper:
    def test_github_org_found_is_inferred(self):
        env = t.wrap_company({"github": {"found": True, "login": "acme"}})
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["confidence"] == 0.70
        assert env["trust"]["extra"]["github_org_found"] is True

    def test_github_org_key_is_an_accepted_alias(self):
        env = t.wrap_company({"github_org": {"login": "acme"}})
        assert env["trust"]["verdict"] == t.INFERRED

    def test_no_github_but_domain_present_is_heuristic(self):
        env = t.wrap_company({"domain": "acme.example"})
        assert env["trust"]["verdict"] == t.HEURISTIC
        assert env["trust"]["confidence"] == 0.40
        assert "no_github_org_social_presence_inferred_from_404" in env["trust"]["warnings"]

    def test_no_data_at_all_is_unverified(self):
        env = t.wrap_company({})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert "no_data_sources_responded" in env["trust"]["warnings"]

    def test_never_exceeds_inferred(self):
        env = t.wrap_company({"github": {"found": True}, "domain": "acme.example"})
        assert env["trust"]["verdict"] != t.VERIFIED


class TestNameWrapper:
    def test_always_heuristic_regardless_of_input(self):
        for raw in ({}, {"username_candidates": ["a", "b"]}, {"anything": "goes"}):
            env = t.wrap_name(raw)
            assert env["trust"]["verdict"] == t.HEURISTIC
            assert env["trust"]["confidence"] == 0.50

    def test_warns_to_verify_via_username_scan(self):
        env = t.wrap_name({})
        assert "feed_to_username_scan_for_verification" in env["trust"]["warnings"]

    def test_result_passthrough_preserves_raw(self):
        raw = {"username_candidates": ["jdoe"]}
        env = t.wrap_name(raw)
        assert env["result"] == raw


class TestWhoisWrapper:
    def test_found_flag_is_verified(self):
        env = t.wrap_whois({"found": True, "registrar": "Example Registrar"})
        assert env["trust"]["verdict"] == t.VERIFIED
        assert env["trust"]["confidence"] == 0.93

    def test_registrar_alone_counts_as_found(self):
        """A raw payload with a registrar field but no explicit 'found'
        flag must still resolve to verified."""
        env = t.wrap_whois({"registrar": "Example Registrar"})
        assert env["trust"]["verdict"] == t.VERIFIED

    def test_no_data_is_unverified(self):
        env = t.wrap_whois({})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert env["trust"]["confidence"] == 0.10
        assert "rdap_lookup_failed" in env["trust"]["warnings"]


class TestSslWrapper:
    def test_has_ssl_flag_is_verified(self):
        env = t.wrap_ssl({"has_ssl": True})
        assert env["trust"]["verdict"] == t.VERIFIED
        assert env["trust"]["confidence"] == 0.96

    def test_certificate_field_alone_counts_as_has_ssl(self):
        env = t.wrap_ssl({"certificate": {"subject": "CN=example.com"}})
        assert env["trust"]["verdict"] == t.VERIFIED

    def test_handshake_failure_is_unverified(self):
        env = t.wrap_ssl({})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert env["trust"]["confidence"] == 0.08
        assert "ssl_handshake_failed_or_no_cert" in env["trust"]["warnings"]


class TestPasteWrapper:
    def test_zero_hits_is_unverified(self):
        env = t.wrap_paste({"results": []})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert "no_hits_in_any_source" in env["trust"]["warnings"]

    def test_hits_key_is_an_accepted_alias_for_results(self):
        env = t.wrap_paste({"hits": [{"url": "x"}]})
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["extra"]["hit_count"] == 1

    def test_one_to_four_hits_is_inferred_055(self):
        env = t.wrap_paste({"results": [{"url": "x"}] * 3})
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["confidence"] == 0.55

    def test_five_or_more_hits_is_inferred_070(self):
        env = t.wrap_paste({"results": [{"url": "x"}] * 5})
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["confidence"] == 0.70

    def test_always_warns_manual_review_required(self):
        env = t.wrap_paste({"results": [{"url": "x"}]})
        assert "results_require_manual_review" in env["trust"]["warnings"]
        assert "relevance_not_guaranteed" in env["trust"]["warnings"]

    def test_never_exceeds_inferred(self):
        env = t.wrap_paste({"results": [{"url": "x"}] * 50})
        assert env["trust"]["verdict"] != t.VERIFIED


class TestMetadataWrapper:
    def test_non_empty_data_is_verified(self):
        env = t.wrap_metadata({"camera_model": "iPhone 15", "gps": {"lat": 1, "lon": 2}})
        assert env["trust"]["verdict"] == t.VERIFIED
        assert env["trust"]["confidence"] == 0.98
        assert "exif_can_be_spoofed_or_stripped" in env["trust"]["warnings"]

    def test_empty_dict_is_unverified(self):
        env = t.wrap_metadata({})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert env["trust"]["confidence"] == 0.10
        assert env["trust"]["errors"] == []

    def test_error_key_present_is_unverified_and_surfaces_the_error(self):
        env = t.wrap_metadata({"error": "unsupported_file_type"})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert "unsupported_file_type" in env["trust"]["errors"]

    def test_local_extraction_can_reach_verified_unlike_networked_wrappers(self):
        """Unlike the network-derived wrappers, local deterministic
        extraction is allowed to hit verified — this pins that this is
        intentional, not an oversight."""
        env = t.wrap_metadata({"width": 100, "height": 100})
        assert env["trust"]["verdict"] == t.VERIFIED


class TestGenericWrapper:
    def test_defaults_to_unverified_unknown(self):
        env = t.wrap_generic({"anything": "goes"})
        assert env["trust"]["verdict"] == t.UNVERIFIED
        assert env["trust"]["method"] == "unknown"
        assert env["trust"]["source"] == "unknown"
        assert env["trust"]["warnings"] == []

    def test_accepts_explicit_verdict_method_source_warnings(self):
        env = t.wrap_generic(
            {"anything": "goes"},
            verdict=t.INFERRED,
            method="custom_adapter",
            source="third_party_api",
            warnings=["adapter_not_yet_mapped_to_a_dedicated_wrapper"],
        )
        assert env["trust"]["verdict"] == t.INFERRED
        assert env["trust"]["method"] == "custom_adapter"
        assert env["trust"]["source"] == "third_party_api"
        assert "adapter_not_yet_mapped_to_a_dedicated_wrapper" in env["trust"]["warnings"]

    def test_invalid_verdict_falls_back_to_unverified(self):
        env = t.wrap_generic({}, verdict="not-a-real-verdict")
        assert env["trust"]["verdict"] == t.UNVERIFIED

    def test_preserves_arbitrary_raw_shapes(self):
        """wrap_generic's raw parameter is typed Any, not dict — it must
        pass through non-dict raw results (e.g. a bare list) unchanged."""
        raw = ["some", "list", "shaped", "result"]
        env = t.wrap_generic(raw)
        assert env["result"] == raw
