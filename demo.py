#!/usr/bin/env python3
"""Runnable showcase for osint-trust-envelope.

Wraps a handful of representative raw OSINT results and prints the trust
verdict each source type is allowed to reach. Run with::

    python demo.py

No network calls, no dependencies — the raw inputs below are illustrative
fixtures, exactly the shape your own adapters would produce.
"""
from __future__ import annotations

from osint_trust_envelope import (
    wrap_breach,
    wrap_domain,
    wrap_email,
    wrap_phone,
    wrap_username_scan,
)


def _show(title: str, env: dict) -> None:
    trust = env["trust"]
    print(f"\n{title}")
    print(f"  verdict    : {trust['verdict']}")
    print(f"  confidence : {trust['confidence']}")
    if trust.get("warnings"):
        print("  warnings   :")
        for w in trust["warnings"][:6]:
            print(f"    - {w}")
    if trust.get("reasoning"):
        print("  reasoning  :")
        for r in trust["reasoning"][:3]:
            print(f"    - {r}")


def main() -> None:
    print("=" * 68)
    print("osint-trust-envelope — verdict ladder demo")
    print("Each source type is capped at the trust level it can honestly reach.")
    print("=" * 68)

    # 1. Phone with one messenger hit. Structurally capped at 'inferred'.
    _show(
        "[1] Phone (+1, libphonenumber, 1 WhatsApp hit) — capped at inferred",
        wrap_phone({
            "parsed": {
                "valid": True,
                "country_code": "+1",
                "enrichment_source": "libphonenumber",
            },
            "social_checks": [{"platform": "WhatsApp", "possible": True}],
        }),
    )

    # 2. Email with strong DMARC + provider. Still cannot exceed 'inferred'.
    _show(
        "[2] Email (MX + Google Workspace + DMARC reject) — capped at inferred",
        wrap_email({
            "validation": {
                "format_valid": True,
                "mx_reachable": True,
                "mx_provider": "Google Workspace",
                "dmarc": {"present": True, "policy": "reject"},
            },
            "services_found": 2,
        }),
    )

    # 3. Username scan, 2 hits, no history. Fragile 404 detection -> heuristic.
    _show(
        "[3] Username scan (2 hits / 10 sites, no history) — heuristic",
        wrap_username_scan({
            "sites_checked": 10,
            "sites_found": 2,
            "results": [{"status": "found"}] * 2 + [{"status": "not_found"}] * 8,
        }),
    )

    # 4. Username scan, 4 independent platforms -> cross-adapter corroboration
    #    promotes heuristic -> inferred.
    _show(
        "[4] Username scan (4 independent platforms) — promoted to inferred",
        wrap_username_scan({
            "sites_checked": 10,
            "sites_found": 4,
            "results": [{"status": "found", "site": f"Site{i}"} for i in range(4)]
            + [{"status": "not_found"}] * 6,
        }),
    )

    # 5. Domain with all four authoritative sources -> verified (still capped).
    _show(
        "[5] Domain (DNS + RDAP + SSL + HTTP) — verified, capped at 0.96",
        wrap_domain({
            "dns": {"a_records": ["1.2.3.4"]},
            "rdap": {"found": True},
            "ssl": {"has_ssl": True},
            "http": {"reachable": True},
        }),
    )

    # 6. Breach: HIBP k-anonymity password check is cryptographically real.
    _show(
        "[6] Breach (HIBP password k-anonymity) — verified",
        wrap_breach({
            "password_check": {"checked": True, "breached": False},
            "email_check": None,
        }),
    )

    print("\n" + "=" * 68)
    print("Note: phone/email/username can never reach 'verified' from these")
    print("signals — that ceiling is enforced in code, not by convention.")
    print("=" * 68)


if __name__ == "__main__":
    main()
