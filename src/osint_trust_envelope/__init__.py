"""osint-trust-envelope — per-source-type epistemic ceilings for OSINT results.

This package wraps a raw OSINT lookup result in a standardized trust envelope
whose verdict is capped at the highest level the *source type* can honestly
support. A phone number cannot be ``verified`` from metadata; an email's
mailbox existence cannot be proven from outside; a 404-scraped username hit is
``heuristic`` by construction. The ceilings are written into the wrappers, not
left to caller discipline.

Public API is re-exported here from :mod:`osint_trust_envelope.trust`.
"""
from __future__ import annotations

from .trust import (
    # verdict vocabulary
    HEURISTIC,
    INFERRED,
    UNVERIFIED,
    VALID_CONTEXTS,
    VALID_VERDICTS,
    VERDICT_DESCRIPTIONS,
    VERDICT_LABELS,
    VERIFIED,
    # core builders
    build_trust,
    # cross-scan corroboration
    corroborate_identities,
    envelope,
    wrap_avatar,
    wrap_breach,
    wrap_company,
    wrap_domain,
    wrap_email,
    wrap_generic,
    wrap_ip,
    wrap_metadata,
    wrap_name,
    wrap_paste,
    wrap_phone,
    wrap_pipeline,
    wrap_ssl,
    # per-adapter wrappers
    wrap_username_scan,
    wrap_whois,
)

__version__ = "0.1.0"

__all__ = [
    "HEURISTIC",
    "INFERRED",
    "UNVERIFIED",
    "VALID_CONTEXTS",
    "VALID_VERDICTS",
    "VERDICT_DESCRIPTIONS",
    "VERDICT_LABELS",
    "VERIFIED",
    "__version__",
    "build_trust",
    "corroborate_identities",
    "envelope",
    "wrap_avatar",
    "wrap_breach",
    "wrap_company",
    "wrap_domain",
    "wrap_email",
    "wrap_generic",
    "wrap_ip",
    "wrap_metadata",
    "wrap_name",
    "wrap_paste",
    "wrap_phone",
    "wrap_pipeline",
    "wrap_ssl",
    "wrap_username_scan",
    "wrap_whois",
]
