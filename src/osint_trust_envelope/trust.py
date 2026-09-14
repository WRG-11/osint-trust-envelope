"""OSINT trust envelope — per-source-type epistemic ceilings as code.

Every OSINT lookup result is wrapped by one of the ``wrap_*`` functions into a
standardized ``{"result": <raw>, "trust": <block>}`` envelope. The trust block
records *how much the caller should believe the result* and — critically —
caps the verdict at the highest level the source TYPE can honestly support.

A phone number can never be ``verified`` from metadata alone (number
portability breaks prefix→carrier inference; messenger presence proves
reachability, not ownership). An email's mailbox existence cannot be proven
from outside (an MX record proves the domain accepts mail, not that THIS
address is read by anyone). A username "hit" from 404-scraping is
``heuristic`` by construction. These ceilings are not configuration — they are
written into the wrappers so a downstream UI or report cannot accidentally
present a structurally-uncertain signal as fact.

Verdict ladder (most trustworthy -> least)
------------------------------------------
* ``verified``   — a real, authoritative source confirmed the result.
                   Example: HIBP k-anonymity password check, an RDAP/DNS
                   lookup that resolved, EXIF parsed from a local file.
* ``inferred``   — real data was retrieved but the interpretation is
                   indirect. Example: an MX record exists (domain is real,
                   mailbox may or may not be), an avatar URL returned HTTP 200
                   (a profile image exists, not that it is the person).
* ``heuristic``  — pattern matching, regex, 404-scraping. False positives
                   are expected. Example: phone country-code lookup, a
                   low-confidence username-scanner hit.
* ``unverified`` — the check was attempted but the source did not respond,
                   was rate-limited, needed a missing API key, or the input
                   was malformed. The honest "we don't know" state.

Confidence 0.0-1.0 orders results *within* a verdict, and its range per verdict
is enforced, not advisory (see ``VERDICT_BANDS`` / ``_enforce_band``):
* verified      -> 0.85 - 1.00
* inferred      -> 0.55 - 0.80
* heuristic     -> 0.25 - 0.55
* unverified    -> 0.00 - 0.20

A number above its band is clamped down; a number below its band demotes the
verdict rather than inflating the number. Both directions claim less.

The package is stdlib-only. Optional historical-reliability enrichment is a
pluggable module-level seam (see ``_get_site_confidences`` /
``_detect_site_anomaly``); the shipped defaults are no-ops, so the core never
depends on an external backend.
"""
from __future__ import annotations

import os
from typing import Any

# -- Verdict constants -------------------------------------------------------
VERIFIED = "verified"
INFERRED = "inferred"
HEURISTIC = "heuristic"
UNVERIFIED = "unverified"

VALID_VERDICTS = {VERIFIED, INFERRED, HEURISTIC, UNVERIFIED}

# Default confidence anchors per verdict
_CONF_ANCHOR = {
    VERIFIED: 0.92,
    INFERRED: 0.68,
    HEURISTIC: 0.40,
    UNVERIFIED: 0.10,
}

# The confidence band each verdict is allowed to occupy. This table IS the
# public contract -- the README's verdict ladder prints exactly these numbers --
# and ``_enforce_band`` below is the only thing that makes the contract true.
#
# The bands are deliberately not contiguous. The gaps (0.20-0.25 and
# 0.80-0.85) are dead zones: a result that lands there is not "between two
# verdicts", it is a wrapper that computed a number its own label cannot back.
VERDICT_BANDS: dict[str, tuple[float, float]] = {
    VERIFIED: (0.85, 1.00),
    INFERRED: (0.55, 0.80),
    HEURISTIC: (0.25, 0.55),
    UNVERIFIED: (0.00, 0.20),
}

# Verdicts strongest-first, for the demotion search in ``_enforce_band``.
_VERDICTS_STRONGEST_FIRST = (VERIFIED, INFERRED, HEURISTIC, UNVERIFIED)

# Human-readable labels for a UI legend.
VERDICT_LABELS = {
    VERIFIED: "Verified",
    INFERRED: "Inferred",
    HEURISTIC: "Heuristic",
    UNVERIFIED: "Unverified",
}

VERDICT_DESCRIPTIONS = {
    VERIFIED: "Real API / authoritative source confirmed. High trust.",
    INFERRED: "Real data retrieved but interpretation is indirect. Moderate trust.",
    HEURISTIC: "Pattern/regex guess. False positive risk.",
    UNVERIFIED: "Could not be verified (source unreachable / key missing).",
}


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _enforce_band(
    verdict: str,
    confidence: float,
    warnings: list[str] | None = None,
) -> tuple[str, float]:
    """Never let a verdict label out-claim its own confidence number.

    Two violations are possible and they are **not** symmetric:

    * confidence ABOVE the band ceiling -> clamp the NUMBER down. The verdict
      tier is the ceiling the source type can support; a number above it is an
      overclaim, and lowering it costs nothing.
    * confidence BELOW the band floor -> demote the VERDICT. Raising the number
      to meet the label would have the library assert more than it measured,
      which is the exact failure this package exists to prevent. So the label
      comes down to the band the number actually lands in.

    Both directions move toward claiming LESS. That asymmetry is the point: a
    naive "clamp into range" would satisfy the invariant while silently
    inflating confidences, turning the guard into an overclaim generator.

    Why this lives in :func:`build_trust` rather than in the wrappers: every
    one of the fifteen ``wrap_*`` functions returns through ``build_trust``, so
    enforcing here reaches all of them by construction and cannot drift out of
    sync with a newly added wrapper. Before this existed the band was enforced
    in exactly one wrapper (``wrap_username_scan``, added in 8b69524 *after*
    the ladders it was meant to police) and measurably failed to reach the
    rest.

    Measured 2026-07-29, before this function existed:

    ==============================  ========================================
    ``wrap_email`` full chain       ``inferred 0.84``  (ceiling is 0.80)
    ``wrap_phone`` + numverify      ``inferred 0.82``  (ceiling is 0.80)
    ``wrap_username_scan`` 3 of 40  ``inferred 0.469`` (floor is 0.55 -- that
                                    number is inside the *heuristic* band)
    ==============================  ========================================
    """
    conf = _clamp(confidence)
    if verdict not in VERDICT_BANDS:
        return verdict, conf

    # A deployment-context cap is a POLICY reduction, not an evidence
    # reduction: `gov` lowers the number it is willing to print, it does not
    # un-observe the RDAP response behind a `verified`. Demoting there would
    # destroy the one fact the operator most needs (the source was
    # authoritative) and would contradict the published contract, which states
    # the cap "only affects confidence, never the verdict tier itself".
    # So the FLOOR is waived once a context cap has fired; the CEILING is not,
    # because clamping down can never overclaim.
    policy_capped = any(w.startswith("context_cap:") for w in (warnings or ()))

    low, high = VERDICT_BANDS[verdict]
    if conf > high:
        if warnings is not None:
            warnings.append(f"band_cap:{verdict}:{high:.2f}")
        return verdict, high
    if conf < low and not policy_capped:
        # Pick the strongest verdict whose band can actually hold this number.
        # A confidence in a DEAD ZONE (e.g. 0.82, below `verified`'s 0.85 floor
        # but above `inferred`'s 0.80 ceiling) belongs to no band at all, so the
        # demotion target's ceiling has to be applied as well -- searching by
        # floor alone lands right back out of band, which is the bug the first
        # cut of this function shipped with.
        demoted, demoted_conf = UNVERIFIED, VERDICT_BANDS[UNVERIFIED][1]
        for candidate in _VERDICTS_STRONGEST_FIRST:
            c_low, c_high = VERDICT_BANDS[candidate]
            if c_low <= conf:
                demoted, demoted_conf = candidate, min(conf, c_high)
                break
        if warnings is not None:
            warnings.append(f"band_demoted:{verdict}->{demoted}")
            if demoted_conf != conf:
                warnings.append(f"band_cap:{demoted}:{demoted_conf:.2f}")
        return demoted, demoted_conf
    return verdict, conf


# -- Optional per-site confidence enrichment (pluggable seam) ----------------
#
# These two hooks are *extension points*, not part of the core trust logic.
# The shipped defaults are no-ops: the trust envelope falls back to its static
# heuristic ladder. To enrich the username-scan verdict with historical
# per-site reliability data, override these module-level functions with your
# own provider, e.g.::
#
#     import osint_trust_envelope.trust as trust
#     trust._get_site_confidences = my_history_lookup   # username -> {site: 0..1}
#     trust._detect_site_anomaly  = my_anomaly_detector # (site, conf) -> dict|None
#
# Keeping these as module-level seams (rather than constructor args) preserves
# the zero-dependency, stdlib-only contract of the core: no enrichment backend
# is bundled, and the wrappers degrade gracefully when none is wired.

def _get_site_confidences(username: str) -> dict[str, float]:
    """Return ``{site: confidence_score 0..1}`` for a username.

    Default implementation is a no-op stub returning ``{}``. Override this
    module-level function to plug in a historical per-site reliability
    provider; the wrappers consult it lazily and degrade to the static ladder
    when it yields nothing.
    """
    return {}


def _detect_site_anomaly(site: str, confidence: float) -> dict[str, Any] | None:
    """Return an anomaly dict when a per-site confidence is a statistical
    outlier, or ``None``.

    Default implementation is a no-op stub returning ``None``. Override this
    module-level function to plug in an anomaly detector that flags per-site
    confidences which deviate from a site's historical baseline.
    """
    return None


# Threshold above which a site is considered "trusted" for strict mode.
STRICT_MODE_MIN_CONFIDENCE = 0.60


def build_trust(
    *,
    verdict: str,
    method: str,
    source: str,
    confidence: float | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    reasoning: list[str] | None = None,
    manual_verify_url: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a trust block. All fields optional except verdict+method+source.

    ``reasoning`` carries 2-3 short human-readable bullets explaining *why*
    the verdict came out — source response characteristics, matched signals,
    contradictions, etc. Operators use this to decide whether to trust or
    manually re-verify a result; feedback loops can later compare stated
    reasoning against the actual operator correction to calibrate anchors.
    """
    if verdict not in VALID_VERDICTS:
        verdict = UNVERIFIED
    if confidence is None:
        confidence = _CONF_ANCHOR[verdict]
    # Single choke point: every wrap_* function returns through here, so the
    # band invariant is enforced once and reaches all of them. See
    # ``_enforce_band`` for why a floor violation demotes rather than inflates.
    warn_list = list(warnings or [])
    verdict, confidence = _enforce_band(verdict, confidence, warn_list)
    block: dict[str, Any] = {
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "method": method,
        "source": source,
        "warnings": warn_list,
        "errors": list(errors or []),
        "reasoning": list(reasoning or []),
    }
    if manual_verify_url:
        block["manual_verify_url"] = manual_verify_url
    if extra:
        block["extra"] = extra
    return block


def envelope(result: Any, trust: dict[str, Any]) -> dict[str, Any]:
    """Wrap a raw adapter result with a trust block.

    The raw adapter response is preserved unchanged under ``result`` so
    existing rendering code that hasn't migrated to the envelope can still
    read it directly via ``response.result.<field>``.
    """
    return {"result": result, "trust": trust}


# Keys every trust block carries, and the type each one promises.
_TRUST_LIST_FIELDS = ("warnings", "errors", "reasoning")


def validate_envelope(envelope_: Any) -> list[str]:
    """Return the contract violations in a trust envelope; empty means clean.

    The package's claim is that a verdict never out-claims its source. That
    claim is only worth anything if a consumer can *check* it, so this turns it
    into an assertion the caller can run on their own side:

        >>> from osint_trust_envelope import validate_envelope, wrap_domain
        >>> validate_envelope(wrap_domain({"rdap": {"found": True}}))
        []

    It is written to be safe on anything -- a hand-built dict, a payload
    deserialised from JSON, an envelope produced by an older version of this
    package -- so it never raises on malformed input; it reports.

    What is checked is the *contract*, not the tradecraft: envelope shape,
    required trust fields and their types, a known verdict, a confidence in
    0-1, and the band invariant (:data:`VERDICT_BANDS`). A confidence below its
    band floor is accepted when a ``context_cap:`` warning explains it, because
    a deployment-context cap lowers the number as policy rather than evidence.

    What is deliberately NOT checked: whether the verdict is the *right* one
    for the data. Nothing outside the caller's own adapters can know that, and
    a validator that pretended otherwise would be the same overclaim in a new
    place.
    """
    problems: list[str] = []

    if not isinstance(envelope_, dict):
        return [f"envelope is {type(envelope_).__name__}, expected dict"]
    if "result" not in envelope_:
        problems.append("missing 'result' key")
    trust = envelope_.get("trust")
    if not isinstance(trust, dict):
        problems.append(
            f"'trust' is {type(trust).__name__}, expected dict")
        return problems

    for field in ("verdict", "confidence", "method", "source"):
        if field not in trust:
            problems.append(f"trust.{field} is missing")
    for field in _TRUST_LIST_FIELDS:
        value = trust.get(field)
        if field not in trust:
            problems.append(f"trust.{field} is missing")
        elif not isinstance(value, list):
            problems.append(
                f"trust.{field} is {type(value).__name__}, expected list")
        elif not all(isinstance(v, str) for v in value):
            problems.append(f"trust.{field} must contain only strings")

    verdict = trust.get("verdict")
    if verdict is not None and verdict not in VALID_VERDICTS:
        problems.append(
            f"trust.verdict {verdict!r} is not one of "
            f"{sorted(VALID_VERDICTS)}")

    conf = trust.get("confidence")
    if not isinstance(conf, (int, float)) or isinstance(conf, bool):
        if "confidence" in trust:
            problems.append(
                f"trust.confidence is {type(conf).__name__}, expected a number")
        return problems
    if not 0.0 <= conf <= 1.0:
        problems.append(f"trust.confidence {conf} is outside 0.0-1.0")
        return problems

    if verdict in VERDICT_BANDS:
        low, high = VERDICT_BANDS[verdict]
        raw_warnings = trust.get("warnings")
        warns: tuple[Any, ...] = tuple(raw_warnings) if isinstance(raw_warnings, list) else ()
        policy_capped = any(
            isinstance(w, str) and w.startswith("context_cap:") for w in warns)
        if conf > high:
            problems.append(
                f"trust.confidence {conf} exceeds the {verdict} ceiling {high}")
        elif conf < low and not policy_capped:
            problems.append(
                f"trust.confidence {conf} is below the {verdict} floor {low} "
                f"and no context_cap warning explains it")

    return problems


# -- Per-adapter wrappers ----------------------------------------------------
#
# Each wrapper takes the raw adapter output and returns the standard envelope.
# These encode the honest trust verdict for that particular source.

CORROBORATION_DEFAULT_PLATFORM_THRESHOLD = 3
CORROBORATION_DEFAULT_PLATFORM_BOOST = 0.15
CORROBORATION_DEFAULT_EMAIL_BOOST = 0.10
CORROBORATION_MAX_TOTAL_BOOST = 0.25
CORROBORATION_CONTRADICTION_HIST_FLOOR = 0.30


# -- Deployment contexts ----------------------------------------------------
#
# Different operational settings tolerate different amounts of false-positive
# risk. A hobbyist ('casual') wants permissive results; a compliance or
# threat-intel deployment ('gov') needs every verdict to be defensible.
# ``confidence_cap`` clamps the final trust confidence so permissive contexts
# can't over-claim, and strict contexts signal lower tolerance even when the
# upstream signals are strong.

VALID_CONTEXTS = ("default", "casual", "strict", "gov")

_CONTEXT_PROFILES: dict[str, dict[str, Any]] = {
    "default": {
        "promotion_boost_min": 0.15,
        "confidence_cap": 1.0,
        "platform_threshold": CORROBORATION_DEFAULT_PLATFORM_THRESHOLD,
    },
    "casual": {
        "promotion_boost_min": 0.10,
        "confidence_cap": 1.0,
        "platform_threshold": 2,
    },
    "strict": {
        "promotion_boost_min": 0.20,
        "confidence_cap": 0.80,
        "platform_threshold": 4,
    },
    "gov": {
        "promotion_boost_min": 0.25,
        "confidence_cap": 0.70,
        "platform_threshold": 5,
    },
}


def _resolve_context(name: str | None) -> dict[str, Any]:
    """Return the profile for a context, falling back to default safely."""
    return _CONTEXT_PROFILES.get(name or "default", _CONTEXT_PROFILES["default"])


def _apply_context_cap(
    conf: float,
    context: str | None,
    warnings: list[str],
    reasoning: list[str] | None = None,
) -> float:
    """Clamp confidence to the deployment context's ceiling; record why.

    Shared by every wrap_* function that accepts a ``context`` kwarg
    (default/casual/strict/gov) so a permissive scan in a stricter
    deployment can't claim more trust than that context allows. Tags the
    non-default context on every call (even when it doesn't end up
    clamping anything) so operators can see which policy was in effect.
    """
    if context and context in VALID_CONTEXTS and context != "default":
        warnings.append(f"context:{context}")
    confidence_cap = float(_resolve_context(context)["confidence_cap"])
    if conf > confidence_cap:
        warnings.append(f"context_cap:{confidence_cap:.2f}")
        if reasoning is not None:
            reasoning.append(
                f"Confidence clamped from {conf:.2f} -> {confidence_cap:.2f} "
                f"by context '{context or 'default'}'."
            )
        conf = confidence_cap
    return conf


# -- Cross-scan identity corroboration --------------------------------------
#
# Given multiple username scan envelopes, detect pairs that share enough
# independent platforms to suggest they belong to the same identity.
# Returns a boost recommendation + evidence per username so the caller can
# re-wrap / enrich downstream without mutating state here.

IDENTITY_MIN_SHARED_PLATFORMS = 5
IDENTITY_BOOST_PER_LINK = 0.12
IDENTITY_MAX_BOOST = 0.20


def _platforms_from_envelope(env: dict[str, Any]) -> set[str]:
    """Extract the set of sites this username was *found* on."""
    try:
        results = env.get("result", {}).get("results", []) or []
    except AttributeError:
        return set()
    sites: set[str] = set()
    for r in results:
        if r.get("status") == "found" and r.get("site"):
            sites.add(str(r["site"]))
    return sites


def corroborate_identities(
    envelopes: list[tuple[str, dict[str, Any]]],
    *,
    min_shared_platforms: int = IDENTITY_MIN_SHARED_PLATFORMS,
    boost_per_link: float = IDENTITY_BOOST_PER_LINK,
    max_boost: float = IDENTITY_MAX_BOOST,
) -> dict[str, dict[str, Any]]:
    """Return per-username identity-corroboration recommendations.

    For each (usernameA, usernameB) pair sharing at least
    ``min_shared_platforms`` independent 'found' sites, emit a boost
    recommendation on BOTH usernames plus the shared platform list so the
    UI can show the evidence.

    The return value is purely advisory — no trust block is mutated here.
    Callers that want to apply the boost should merge it into the existing
    envelope's ``trust.confidence`` (clamped to the context cap they own)
    and append the reasoning bullets.

    Shape:
        {
          "alice": {
             "boost": 0.12,
             "links": [
                {"other": "bob", "shared_platforms": ["GitHub", ...],
                 "shared_count": 6}
             ],
             "reasoning": ["Shares 6 platforms with 'bob' ..."],
          },
          ...
        }
    """
    # Extract found-platform sets per username.
    user_platforms: dict[str, set[str]] = {
        username: _platforms_from_envelope(env) for username, env in envelopes
    }

    # Pair scan: symmetric boost for qualifying links.
    result: dict[str, dict[str, Any]] = {}
    usernames = list(user_platforms.keys())
    for i, u1 in enumerate(usernames):
        for u2 in usernames[i + 1:]:
            shared = user_platforms[u1] & user_platforms[u2]
            if len(shared) < min_shared_platforms:
                continue
            for a, b in ((u1, u2), (u2, u1)):
                entry = result.setdefault(a, {"boost": 0.0, "links": [], "reasoning": []})
                entry["links"].append({
                    "other": b,
                    "shared_platforms": sorted(shared),
                    "shared_count": len(shared),
                })
                entry["reasoning"].append(
                    f"Shares {len(shared)} platform(s) with '{b}' "
                    f"(>={min_shared_platforms}) - likely same identity."
                )
                entry["boost"] = round(min(max_boost, entry["boost"] + boost_per_link), 3)

    return result


def wrap_username_scan(
    raw: dict[str, Any],
    *,
    username: str | None = None,
    strict: bool = False,
    corroborating_email: str | None = None,
    platform_boost_threshold: int | None = None,
    platform_boost_amount: float = CORROBORATION_DEFAULT_PLATFORM_BOOST,
    email_match_boost: float = CORROBORATION_DEFAULT_EMAIL_BOOST,
    context: str | None = None,
) -> dict[str, Any]:
    """Username scanner trust envelope.

    Pure-heuristic mode (no ``username``): falls back to the historic ladder
    where any 404-based detection is capped at ``HEURISTIC`` / 0.55.

    Confidence-aware mode (``username`` given): looks up the historical
    per-site reliability score via the ``_get_site_confidences`` seam and:
        * annotates each result with ``historical_confidence``
        * raises the overall trust confidence proportional to the average
          score of hit sites (still capped — see below)
        * if ``strict=True``, drops any "found" hit whose historical
          confidence is below ``STRICT_MODE_MIN_CONFIDENCE`` and records
          how many were filtered.

    Two no-result states to distinguish:

    * **Clean negative** (``sites_found=0``, N sites responded): yields
      ``inferred`` 0.60. Absence of a handle across N real checks is
      evidence the handle does not exist there.
    * **Adapter error** (scanner could not run -- binary missing, timeout):
      pass ``sites_checked=0`` with an empty ``results`` list. Yields
      ``unverified`` -- the honest "no data" state, not a negative signal.
    """
    if not isinstance(raw, dict):
        raw = {}
    warnings: list[str] = []
    reasoning: list[str] = []
    context_profile = _resolve_context(context)
    if platform_boost_threshold is None:
        platform_boost_threshold = int(context_profile["platform_threshold"])
    promotion_boost_min = float(context_profile["promotion_boost_min"])
    confidence_cap = float(context_profile["confidence_cap"])

    # The caller passes the raw username-scan dict:
    # {sites_checked, sites_found, results: [...]}.
    raw_results = [r for r in (raw.get("results") or []) if isinstance(r, dict)]
    err_count = sum(1 for r in raw_results if r.get("status") == "error")
    # How many sites actually responded at all -- independent of strict
    # mode's confidence filtering below, which only drops "found" hits for
    # being low-confidence. A site that answered "found" but got filtered
    # for low confidence still RESPONDED; it did not error, and using the
    # post-filter count here would let strict-mode filtering manufacture a
    # majority-error verdict out of a scan that mostly worked. See
    # ``checked_after`` for the (deliberately different) post-filter count
    # used for the confidence-ratio math and the reported extras.
    responded_count = len(raw_results)
    parking_hits = sum(
        1 for r in raw_results
        if r.get("status") == "not_found" and "parking" in str(r.get("message", "")).lower()
    )

    # -- Per-site confidence enrichment --------------------------------------
    site_confs = _get_site_confidences(username) if username else {}
    enriched: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []
    for r in raw_results:
        rr = dict(r)
        site = rr.get("site", "")
        if site and site in site_confs:
            hc = round(site_confs[site], 4)
            rr["historical_confidence"] = hc
            # Only run anomaly check on "found" hits — anomalies on misses
            # don't change the verdict and create noise.
            if rr.get("status") == "found":
                anomaly = _detect_site_anomaly(site, hc)
                if anomaly:
                    rr["anomaly"] = anomaly
                    anomalies.append({"site": site, **anomaly})
        enriched.append(rr)

    # -- Strict mode filter (only on the "found" subset) ---------------------
    filtered_low_conf = 0
    if strict and site_confs:
        new_results: list[dict[str, Any]] = []
        for rr in enriched:
            if rr.get("status") == "found":
                hc = rr.get("historical_confidence", 0.0)
                if hc < STRICT_MODE_MIN_CONFIDENCE:
                    filtered_low_conf += 1
                    continue
            new_results.append(rr)
        enriched = new_results

    # Recompute counts AFTER strict filter so the UI sees consistent numbers.
    found_after = sum(1 for r in enriched if r.get("status") == "found")
    checked_after = len(enriched)

    if checked_after == 0:
        verdict, conf = UNVERIFIED, 0.05
        warnings.append("no_sites_checked")
        reasoning.append("No sites reached - cannot form any verdict.")
    elif err_count > responded_count * 0.5:
        verdict, conf = UNVERIFIED, 0.15
        warnings.append("majority_sites_errored")
        reasoning.append(
            f"{err_count}/{responded_count} sites errored - majority failure invalidates the scan."
        )
    elif found_after == 0:
        verdict, conf = INFERRED, 0.60
        warnings.append("no_hits_but_sites_responded")
        reasoning.append(
            f"{checked_after} sites responded cleanly, zero hits - strong negative signal."
        )
        if parking_hits > 0:
            reasoning.append(
                f"{parking_hits} candidate hits rejected as parking/for-sale landing pages."
            )
        if filtered_low_conf > 0:
            warnings.append(f"strict_mode_dropped_{filtered_low_conf}_low_confidence_hits")
            reasoning.append(
                f"Strict mode dropped {filtered_low_conf} low-confidence hits before aggregation."
            )
    else:
        # Mix of heuristic+real. 404-based detection is fundamentally fragile.
        verdict = HEURISTIC
        # Base confidence (legacy ladder, capped at 0.55).
        conf = min(0.55, 0.30 + (found_after / max(checked_after, 1)) * 0.25)
        warnings.append("http_status_based_detection")
        warnings.append("verify_hits_manually")
        reasoning.append(
            f"{found_after}/{checked_after} sites returned the expected status - baseline heuristic hit."
        )
        if parking_hits > 0:
            reasoning.append(
                f"Rejected {parking_hits} additional candidates as parking/for-sale pages "
                "(title + body-pattern + size checks)."
            )

        # Bonus from historical per-site reliability for hit sites only.
        hit_scores = [
            r.get("historical_confidence", 0.0)
            for r in enriched
            if r.get("status") == "found" and "historical_confidence" in r
        ]
        if hit_scores:
            avg_hist = sum(hit_scores) / len(hit_scores)
            # Anchor: the historical confidence pulls the trust up but caps at
            # 0.78 — we never claim 'verified' from 404 scraping, even with a
            # perfect track record.
            boosted = 0.40 + avg_hist * 0.40
            conf = max(conf, min(0.78, boosted))
            reasoning.append(
                f"Average historical reliability of hit sites: {avg_hist:.2f}."
            )
            if avg_hist >= 0.70:
                # Full upgrade: stable historical hits earn 'inferred' status.
                verdict = INFERRED
                warnings.append("history_backed_inference")
                reasoning.append("Promoted to 'inferred' on strong historical track record.")

        # -- Cross-adapter corroboration -------------------------------------
        # Boost trust when independent signals agree. Contradictions (many
        # hits from historically-unreliable sites) halve the boost and raise
        # a dedicated warning so operators can spot the pattern.
        corroboration_boost = 0.0
        if found_after >= platform_boost_threshold:
            corroboration_boost += platform_boost_amount
            warnings.append(f"corroboration:{found_after}_platforms")
            reasoning.append(
                f"Hit on {found_after} independent platforms (>={platform_boost_threshold}) -> "
                f"+{platform_boost_amount:.2f} corroboration boost."
            )
        if corroborating_email and found_after > 0:
            corroboration_boost += email_match_boost
            warnings.append("corroboration:email_username_co_occurrence")
            reasoning.append(
                f"Co-occurring email '{corroborating_email}' supplied by caller -> "
                f"+{email_match_boost:.2f} identity corroboration."
            )

        contradiction = False
        if found_after >= platform_boost_threshold and hit_scores:
            avg_hc = sum(hit_scores) / len(hit_scores)
            if avg_hc < CORROBORATION_CONTRADICTION_HIST_FLOOR:
                contradiction = True
                warnings.append("contradiction:many_hits_low_site_reliability")
                reasoning.append(
                    f"Contradiction: {found_after} hits but average site reliability "
                    f"{avg_hc:.2f} < {CORROBORATION_CONTRADICTION_HIST_FLOOR:.2f} - boost halved."
                )
                corroboration_boost *= 0.5

        if corroboration_boost > 0:
            corroboration_boost = min(corroboration_boost, CORROBORATION_MAX_TOTAL_BOOST)
            conf = _clamp(conf + corroboration_boost)
            # Significant boost on a still-heuristic verdict promotes to
            # inferred — but only when there is no contradiction flag and
            # the boost clears the context-specific minimum.
            #
            # The promotion test and the confidence must answer to the SAME
            # yardstick. The boost qualifies on the ABSOLUTE number of
            # independent platforms; ``conf`` is computed from the hit RATIO.
            # On a wide scan those diverge badly: 3 hits across 40 responding
            # sites cleared the 3-platform bar while the confidence sat at
            # 0.469 -- a number inside the *heuristic* band. Promoting there
            # printed an 'inferred' label over a heuristic number, which is
            # the overclaim this package exists to prevent. Sparse-but-wide is
            # the normal shape of a real username scan, not an edge case.
            inferred_floor = VERDICT_BANDS[INFERRED][0]
            if verdict == HEURISTIC and corroboration_boost >= promotion_boost_min and not contradiction:
                if conf >= inferred_floor:
                    verdict = INFERRED
                    warnings.append("cross_adapter_corroboration_promotion")
                    reasoning.append(
                        f"Promoted heuristic -> inferred on strong cross-adapter agreement "
                        f"(boost {corroboration_boost:.2f} >= context floor {promotion_boost_min:.2f})."
                    )
                else:
                    warnings.append("corroboration_below_inferred_floor")
                    reasoning.append(
                        f"Cross-adapter agreement cleared the boost floor "
                        f"({corroboration_boost:.2f} >= {promotion_boost_min:.2f}) but the resulting "
                        f"confidence {conf:.3f} stays under the 'inferred' band floor "
                        f"{inferred_floor:.2f} - verdict held at heuristic."
                    )

    if err_count > 0:
        warnings.append(f"{err_count}_sites_errored")
    if site_confs:
        warnings.append("per_site_history_applied")
    if strict:
        warnings.append("strict_mode_active")
    # Context confidence cap: a permissive scan in a gov/strict deployment
    # must not claim more trust than the context permits.
    conf = _apply_context_cap(conf, context, warnings, reasoning)
    # The 'inferred' ceiling used to be re-implemented here, inline, and only
    # here -- which is exactly why wrap_email and wrap_phone drifted past it.
    # It now lives in _enforce_band(), applied by build_trust() for every
    # wrapper. Nothing replaces it at this spot on purpose.
    if anomalies:
        high = [a for a in anomalies if a.get("direction") == "high"]
        low = [a for a in anomalies if a.get("direction") == "low"]
        warnings.append(f"confidence_anomaly:{len(anomalies)}_sites")
        if high:
            reasoning.append(
                f"{len(high)} hit(s) have unusually HIGH historical confidence "
                f"(>=3sigma above site mean) - possible poisoning or unique track record."
            )
        if low:
            reasoning.append(
                f"{len(low)} hit(s) have unusually LOW historical confidence "
                f"(<=3sigma below site mean) - treat with extra skepticism."
            )

    # The envelope still preserves the original raw counts for legacy clients
    # but exposes enriched results + post-filter counts via ``extra``.
    raw_out = dict(raw)
    raw_out["results"] = enriched
    raw_out["sites_checked"] = checked_after
    raw_out["sites_found"] = found_after

    return envelope(
        raw_out,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="http_status_code+history_db" if site_confs else "http_status_code",
            source="username sites (urllib) + optional history provider",
            warnings=warnings,
            errors=[],
            reasoning=reasoning[:5],
            extra={
                "sites_checked": checked_after,
                "sites_found": found_after,
                "sites_errored": err_count,
                "parking_rejected": parking_hits,
                "per_site_reliable": found_after,
                "history_sites_known": len(site_confs),
                "strict_mode": bool(strict),
                "filtered_low_confidence": filtered_low_conf,
                "anomalies_detected": len(anomalies),
                "anomalies": anomalies[:10],
                "context": context or "default",
                "context_confidence_cap": confidence_cap,
            },
        ),
    )


def wrap_email(raw: dict[str, Any], *, context: str | None = None) -> dict[str, Any]:
    """Email OSINT trust envelope (tier-2).

    Confidence ladder (cumulative — best signal in the chain wins):

        bad format                                   → unverified 0.05
        format + MX (no DMARC, no provider)          → heuristic  0.40
        format + MX + provider classified            → heuristic  0.50
        format + MX + DMARC=none                     → inferred   0.60
        format + MX + DMARC=quarantine|reject        → inferred   0.70
        + Gravatar/GitHub/Keybase hit (services>0)   → inferred   0.78
        + provider + DMARC strict + services>0
            + not disposable + not role              → inferred   0.80

    Hard cap: ``inferred``. We never reach ``verified`` because:
        * an MX record proves the domain accepts mail, not that THIS mailbox
          exists or is read by the target;
        * forwarders, aliases and catch-all rules are invisible from
          outside;
        * SPF/DMARC tell us how the domain wants to be handled, not who
          owns the address.
    """
    if not isinstance(raw, dict):
        raw = {}
    validation = raw.get("validation", {}) or {}
    format_valid = bool(validation.get("format_valid"))
    mx_reachable = bool(validation.get("mx_reachable"))
    mx_records = validation.get("mx_records") or []
    mx_provider = validation.get("mx_provider")
    spf = validation.get("spf") or {}
    dmarc = validation.get("dmarc") or {}
    role_account = validation.get("role_account") or {}
    disposable = bool(validation.get("disposable"))
    is_role = bool(role_account.get("is_role"))
    services_found = int(raw.get("services_found", 0) or 0)

    spf_present = bool(spf.get("present"))
    spf_all_qualifier = spf.get("all_qualifier")  # '+', '-', '~', '?'
    dmarc_present = bool(dmarc.get("present"))
    dmarc_policy = (dmarc.get("policy") or "").lower()
    dmarc_strict = dmarc_policy in ("quarantine", "reject")

    warnings: list[str] = []
    errors: list[str] = []

    # Mandatory honesty disclaimers — phone-style.
    mandatory_warnings = [
        "mailbox_existence_not_proven",
        "aliases_and_forwarders_invisible",
    ]

    # -- Bad format ---------------------------------------------------------
    if not format_valid:
        errors.append("invalid_email_format")
        _apply_context_cap(0.05, context, mandatory_warnings)
        return envelope(
            raw,
            build_trust(
                verdict=UNVERIFIED,
                confidence=0.05,
                method="rfc5322_regex",
                source="local format check",
                warnings=mandatory_warnings,
                errors=errors,
                reasoning=[
                    "Address failed the RFC-5322 format check - no lookup was "
                    "attempted, so this is 'no data', not 'no mailbox'.",
                ],
                extra={
                    "format_valid": False,
                    "mx_reachable": False,
                    "services_found": 0,
                },
            ),
        )

    # -- Climb the ladder ---------------------------------------------------
    verdict, conf = HEURISTIC, 0.30

    if mx_reachable:
        verdict, conf = HEURISTIC, 0.40
        if mx_provider:
            conf = 0.50
        if dmarc_present:
            verdict, conf = INFERRED, 0.60
            if dmarc_strict:
                conf = 0.70
        if services_found > 0 and verdict == INFERRED:
            conf = max(conf, 0.78)
        if (
            verdict == INFERRED
            and not disposable
            and not is_role
            and mx_provider
            and dmarc_strict
            and services_found > 0
        ):
            # Top of the inferred band, read from the band table rather than
            # hardcoded: this rung used to be 0.84, four points ABOVE the
            # ceiling the README publishes, and nothing caught it.
            conf = max(conf, VERDICT_BANDS[INFERRED][1])
    else:
        warnings.append("mx_lookup_failed_or_unreachable")

    # -- Conditional warnings -----------------------------------------------
    if disposable:
        warnings.append("disposable_provider")
    if is_role:
        warnings.append(f"role_account:{role_account.get('matched','?')}")
    if mx_reachable and not dmarc_present:
        warnings.append("no_dmarc_record")
    if mx_reachable and dmarc_present and not dmarc_strict:
        warnings.append("dmarc_policy_none_no_enforcement")
    if spf_present and spf_all_qualifier == "+":
        warnings.append("spf_all_open_relay_risk")
    if not mx_records and mx_reachable:
        # Reachability inferred from A-record fallback only.
        warnings.append("mx_inferred_from_a_record_fallback")
    if raw.get("breach_summary") is None and format_valid:
        warnings.append("breach_check_skipped_or_unavailable")

    # Why this verdict came out, in the order the ladder climbed it.
    reasoning: list[str] = []
    if mx_reachable:
        reasoning.append(
            f"MX resolves ({len(mx_records)} record(s), provider "
            f"{mx_provider or 'unrecognised'}) - the domain accepts mail."
        )
    else:
        reasoning.append(
            "No MX reachable - the domain may not accept mail at all.")
    if dmarc_present:
        reasoning.append(
            f"DMARC policy '{dmarc_policy or 'none'}'"
            + (" is enforcing - the domain is actively administered."
               if dmarc_strict else
               " is monitor-only - there is no enforcement to lean on.")
        )
    else:
        reasoning.append(
            "No DMARC record - nothing corroborates how the domain is run.")
    if services_found > 0:
        reasoning.append(
            f"{services_found} external service(s) recognised this address.")
    blockers = [
        label for label, hit in
        (("disposable provider", disposable), ("role account", is_role))
        if hit
    ]
    if blockers:
        reasoning.append(
            f"Held below the top rung: {' + '.join(blockers)}.")
    reasoning.append(
        "Mailbox existence is not observable from outside - hard ceiling: inferred.")

    warnings = mandatory_warnings + warnings
    conf = _apply_context_cap(conf, context, warnings)

    extra: dict[str, Any] = {
        "format_valid": True,
        "mx_reachable": mx_reachable,
        "services_found": services_found,
        "mx_provider": mx_provider,
        "mx_count": len(mx_records),
        "spf_present": spf_present,
        "spf_all_qualifier": spf_all_qualifier,
        "dmarc_present": dmarc_present,
        "dmarc_policy": dmarc_policy or None,
        "disposable": disposable,
        "role_account": role_account.get("matched") if is_role else None,
        "context": context or "default",
    }

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="doh_mx + spf + dmarc + gravatar + github",
            source="Google DoH + Gravatar + GitHub + HIBP",
            warnings=warnings,
            errors=errors,
            reasoning=reasoning[:5],
            extra=extra,
        ),
    )


def wrap_phone(raw: dict[str, Any], *, context: str | None = None) -> dict[str, Any]:
    """Phone OSINT trust envelope.

    Confidence ladder (no paid API path):
        regex-only fallback         → heuristic 0.35
        libphonenumber parse        → heuristic 0.55
        + 1 messenger presence hit  → inferred  0.66
        + 2 messenger presence hits → inferred  0.74
        + Numverify API confirmed   → inferred  0.80  (top of band — MNP)

    The verdict NEVER becomes ``verified`` because:
        * libphonenumber's "carrier" is the original prefix allocation,
          which is wrong after number portability (MNP).
        * Messenger presence proves the number is REACHABLE, not who owns it.
        * Numverify gives a *current* carrier but cannot prove identity.
    """
    if not isinstance(raw, dict):
        raw = {}
    parsed = raw.get("parsed", {}) or {}
    valid_format = bool(parsed.get("valid"))
    enrichment_source = parsed.get("enrichment_source") or "regex"
    used_libphonenumber = enrichment_source == "libphonenumber"

    warnings: list[str] = []
    errors: list[str] = []

    if not valid_format:
        verdict, conf = UNVERIFIED, 0.05
        errors.append("invalid_phone_format")
        warnings.append("number_did_not_parse")
        return envelope(
            raw,
            build_trust(
                verdict=verdict,
                confidence=conf,
                method="phonenumbers" if used_libphonenumber else "e164_regex",
                source="libphonenumber" if used_libphonenumber else "local regex tables",
                warnings=warnings,
                errors=errors,
                reasoning=[
                    "The number did not parse - no enrichment was attempted, so "
                    "this is 'unparseable input', not 'unused number'.",
                ],
                extra={
                    "valid_format": False,
                    "enrichment_source": enrichment_source,
                },
            ),
        )

    # Baseline: parsed format + country/region. The MNP caveat is permanent.
    warnings.append("number_portability_not_reflected")
    warnings.append("ownership_not_determinable_from_number_alone")

    if used_libphonenumber:
        verdict, conf = HEURISTIC, 0.55
        warnings.append("parsed_via_libphonenumber")
    else:
        verdict, conf = HEURISTIC, 0.35
        warnings.append("parsed_via_regex_fallback")
        warnings.append("install_phonenumbers_for_better_data")

    # -- Messenger presence boost -------------------------------------------
    # WhatsApp/Telegram presence is a strong "reachable + active" signal even
    # though it doesn't reveal identity. We weigh both checks and use the
    # cumulative hit count to bump the verdict.
    social = raw.get("social_checks") or []
    if isinstance(social, list):
        hits = [s for s in social if isinstance(s, dict) and s.get("possible")]
        hit_count = len(hits)
    else:
        hits = []
        hit_count = 0

    if hit_count >= 1:
        # Even one hit upgrades us out of pure heuristic territory: we have
        # external corroboration that the number is in use.
        verdict = INFERRED
        if hit_count == 1:
            conf = max(conf, 0.66)
            warnings.append("single_messenger_presence_only")
        else:
            conf = max(conf, 0.74)
        warnings.append(f"messenger_presence_hits={hit_count}")

    # -- Optional Numverify (paid API) bump ---------------------------------
    # If a NUMVERIFY_API_KEY is present and the call succeeded, the result
    # has a *current* carrier rather than the prefix's original allocation.
    # We still cap below the verified threshold because Numverify themselves
    # disclaim that it can be stale.
    reverse = raw.get("reverse_lookup", {}) or {}
    if reverse.get("lookup_done"):
        verdict = INFERRED
        # Top of the inferred band (was a hardcoded 0.82, i.e. two points over
        # the published ceiling). A reverse lookup is the strongest phone
        # signal there is, so it earns the top of the band -- and no more.
        conf = max(conf, VERDICT_BANDS[INFERRED][1])
        warnings.append("numverify_api_confirmed")
        # Drop the now-stale prefix-only caveats — we have a real carrier.
        for w in (
            "parsed_via_libphonenumber",
            "parsed_via_regex_fallback",
            "install_phonenumbers_for_better_data",
        ):
            if w in warnings:
                warnings.remove(w)
        warnings.append("carrier_from_third_party_api_may_be_stale")
    elif reverse.get("skipped_reason"):
        warnings.append(f"reverse_lookup_skipped:{reverse.get('skipped_reason')}")

    reasoning: list[str] = [
        f"Number parsed via {'libphonenumber' if used_libphonenumber else 'the regex fallback'}"
        + (f" ({parsed.get('country_code')})." if parsed.get("country_code") else ".")
    ]
    if hit_count:
        reasoning.append(
            f"{hit_count} messenger presence hit(s) "
            f"({', '.join(str(s.get('platform')) for s in hits)}) - the number is "
            f"reachable and in use, which is not the same as knowing who holds it."
        )
    else:
        reasoning.append(
            "No messenger presence - nothing external corroborates that the "
            "number is in use.")
    if reverse.get("lookup_done"):
        reasoning.append(
            "A reverse lookup returned a CURRENT carrier, which beats the "
            "prefix allocation - but a carrier is still not an identity.")
    reasoning.append(
        "Number portability breaks prefix-to-carrier inference - hard ceiling: inferred.")

    conf = _apply_context_cap(conf, context, warnings)

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method=("phonenumbers + messenger_presence + numverify"
                    if reverse.get("lookup_done")
                    else "phonenumbers + messenger_presence"
                    if used_libphonenumber
                    else "e164_regex + prefix_table"),
            source=("libphonenumber + wa.me + t.me + numverify"
                    if reverse.get("lookup_done")
                    else "libphonenumber + wa.me + t.me"
                    if used_libphonenumber
                    else "local regex tables"),
            warnings=warnings,
            errors=errors,
            reasoning=reasoning[:5],
            extra={
                "valid_format": valid_format,
                "enrichment_source": enrichment_source,
                "country_code": parsed.get("country_code"),
                "iso": parsed.get("iso"),
                "region": parsed.get("region") or parsed.get("region_tr"),
                "line_type": parsed.get("line_type"),
                "carrier": parsed.get("carrier"),
                "carrier_source": parsed.get("carrier_source"),
                "messenger_hits": hit_count,
                "messengers_checked": [
                    s.get("platform") for s in social if isinstance(s, dict)
                ],
                "numverify_used": bool(reverse.get("lookup_done")),
                "context": context or "default",
            },
        ),
    )


def wrap_ip(raw: dict[str, Any], *, context: str | None = None) -> dict[str, Any]:
    """IP OSINT — tier-2 ladder.

    Verdicts:
      no data at all                          → unverified 0.10
      partial (1 of 3 base sources)           → inferred   0.55
      2 of 3 base sources                     → verified   0.82
      3 of 3 base sources                     → verified   0.92
      + Tor exit node (any tier)              → verified caps at 0.95
      + DNSBL listed                          → adds warning, no boost
      + ASN classified (cloud/host/mobile/...)→ adds context, no boost
    """
    if not isinstance(raw, dict):
        raw = {}
    geo = raw.get("geolocation", {}) or {}
    rdap = raw.get("rdap", {}) or {}
    rdns = raw.get("reverse_dns", {}) or {}
    tor = raw.get("tor", {}) or {}
    dnsbl = raw.get("dnsbl", {}) or {}
    asn = raw.get("asn_classification", {}) or {}

    geo_found = bool(geo.get("found"))
    rdap_found = bool(rdap.get("found"))
    rdns_hostname = rdns.get("hostname")

    is_tor = bool(tor.get("is_tor"))
    dnsbl_listed = bool(dnsbl.get("listed"))
    dnsbl_hits = list(dnsbl.get("hits") or [])
    asn_class = asn.get("class") or "unknown"
    asn_label = asn.get("label")

    warnings: list[str] = []
    successful = sum([geo_found, rdap_found, bool(rdns_hostname)])

    # Base ladder
    if successful == 0:
        verdict, conf = UNVERIFIED, 0.10
        warnings.append("all_ip_lookups_failed")
        warnings.append("ip_api_or_rdap_unreachable")
    elif successful == 3:
        verdict, conf = VERIFIED, 0.92
    elif successful == 2:
        verdict, conf = VERIFIED, 0.82
        warnings.append("one_source_missing")
    else:
        verdict, conf = INFERRED, 0.55
        warnings.append("only_partial_ip_data")

    # Hard caps for private / loopback
    if raw.get("ip_type") in ("private", "loopback"):
        warnings.append("private_ip_no_public_intel")

    # Tor: very high signal — promote to verified, ceil at 0.95
    if is_tor:
        verdict = VERIFIED
        conf = max(conf, 0.95)
        warnings.append("tor_exit_node")

    # DNSBL: warning per hit, no confidence change (the list itself is opinionated)
    if dnsbl_listed:
        for hit in dnsbl_hits:
            warnings.append(f"dnsbl_listed:{hit.get('name', 'unknown')}")
    elif dnsbl.get("skipped_reason"):
        # not a real signal, just transparency
        pass

    # ASN classification context
    if asn_class == "cloud" and asn_label:
        warnings.append(f"cloud_provider:{asn_label}")
        warnings.append("datacenter_ip_no_human")
    elif asn_class == "hosting":
        warnings.append("datacenter_ip_no_human")
    elif asn_class == "mobile":
        warnings.append("mobile_carrier_ip_dynamic_assignment")

    # Mandatory honesty disclaimers — always present so consumers can't forget
    warnings.append("ip_geolocation_is_isp_level_not_user_level")

    answered = [
        label for label, hit in
        (("geolocation", geo_found), ("RDAP", rdap_found),
         ("reverse DNS", bool(rdns_hostname)))
        if hit
    ]
    reasoning: list[str] = [
        f"{successful} of 3 base sources answered"
        + (f" ({', '.join(answered)})." if answered else " - none of them.")
    ]
    if is_tor:
        reasoning.append(
            "The address is on a published Tor exit list - an authoritative "
            "membership fact, independent of whether the other lookups worked.")
    if dnsbl_listed:
        reasoning.append(
            f"Listed on {len(dnsbl_hits)} blocklist(s) - reputational context, "
            f"deliberately not folded into the confidence.")
    if asn_class in ("cloud", "hosting", "mobile"):
        reasoning.append(
            f"ASN classified as {asn_class}"
            + (f" ({asn_label})" if asn_label else "")
            + " - shapes who is likely behind the address.")
    reasoning.append(
        "Geolocation resolves to the ISP, never to a person.")

    conf = _apply_context_cap(conf, context, warnings)

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="socket + ip-api.com + rdap.org + tor list + DNSBL + ASN class",
            source="ip-api.com + rdap.org + local DNS + check.torproject.org + DNSBLs",
            warnings=warnings,
            errors=[],
            reasoning=reasoning[:5],
            extra={
                "geolocation_found": geo_found,
                "rdap_found": rdap_found,
                "reverse_dns_found": bool(rdns_hostname),
                "ip_type": raw.get("ip_type"),
                "is_tor": is_tor,
                "tor_list_size": tor.get("list_size") or 0,
                "tor_skipped_reason": tor.get("skipped_reason"),
                "is_dnsbl_listed": dnsbl_listed,
                "dnsbl_hits": [h.get("name") for h in dnsbl_hits],
                "dnsbl_checked": bool(dnsbl.get("checked")),
                "dnsbl_skipped_reason": dnsbl.get("skipped_reason"),
                "asn_class": asn_class,
                "asn_label": asn_label,
                "is_cloud_provider": asn_class == "cloud",
                "is_datacenter": asn_class in ("cloud", "hosting"),
                "context": context or "default",
            },
        ),
    )


def wrap_domain(raw: dict[str, Any], *, context: str | None = None) -> dict[str, Any]:
    """Domain OSINT — tier-2 ladder.

    Base verdicts (from DNS + RDAP + SSL + HTTP):
      0 of 4    → unverified 0.08
      1 of 4    → inferred   0.55
      2 of 4    → verified   0.80
      3+ of 4   → verified   0.92

    Tier-2 boosts (additive, capped at 0.96):
      + DNSSEC validated     +0.02
      + CT log harvest hits  +0.02 (real cert history is hard to fake)
      + SSL deep healthy     +0.02 (modern TLS + strong cipher + SAN match)

    Tier-2 warnings (no confidence change):
      no_dnssec_validation, no_spf_record, no_dmarc_record,
      ct_log_unavailable, ct_revealed_<n>_subdomains,
      ssl_expired / ssl_expires_soon_<n>_days, tls_insecure_protocol,
      tls_legacy_protocol, tls_weak_cipher, ssl_san_mismatch,
      ssl_self_signed
    """
    if not isinstance(raw, dict):
        raw = {}
    rdap = raw.get("rdap", {}) or {}
    ssl = raw.get("ssl", {}) or {}
    http = raw.get("http", {}) or {}
    dns = raw.get("dns", {}) or {}
    ct = raw.get("ct_logs", {}) or {}
    ct_alive = raw.get("ct_alive", {}) or {}
    dnssec = raw.get("dnssec", {}) or {}
    auth = raw.get("email_auth", {}) or {}
    spf = (auth.get("spf") or {}) if isinstance(auth, dict) else {}
    dmarc = (auth.get("dmarc") or {}) if isinstance(auth, dict) else {}

    rdap_found = bool(rdap.get("found"))
    has_ssl = bool(ssl.get("has_ssl"))
    http_reachable = bool(http.get("reachable"))
    has_dns = bool(dns.get("a_records") or dns.get("aaaa_records"))

    dnssec_validated = bool(dnssec.get("validated"))
    dnssec_checked = bool(dnssec.get("checked"))
    ct_count = int(ct.get("count") or 0)
    ct_alive_count = len(ct_alive.get("alive") or [])
    spf_present = bool(spf.get("present"))
    dmarc_present = bool(dmarc.get("present"))
    dmarc_policy = (dmarc.get("policy") or "").lower()

    # Tier-2 SSL deep inspection signals
    ssl_protocol_class = ssl.get("protocol_class")
    ssl_cipher_class = ssl.get("cipher_class")
    ssl_cipher_name = ssl.get("cipher_name")
    ssl_cipher_bits = ssl.get("cipher_bits")
    ssl_expiry_status = ssl.get("expiry_status")
    ssl_days_to_expiry = ssl.get("days_to_expiry")
    ssl_san_match = ssl.get("san_match")
    ssl_self_signed = ssl.get("is_self_signed")
    ssl_fingerprint = ssl.get("sha256_fingerprint")

    warnings: list[str] = []
    successful = sum([rdap_found, has_ssl, http_reachable, has_dns])

    # Base ladder
    if successful == 0:
        verdict, conf = UNVERIFIED, 0.08
        warnings.append("domain_unreachable")
    elif successful >= 3:
        verdict, conf = VERIFIED, 0.92
    elif successful == 2:
        verdict, conf = VERIFIED, 0.80
        warnings.append("some_lookups_failed")
    else:
        verdict, conf = INFERRED, 0.55
        warnings.append("only_one_source_responded")

    # Tier-2 boosts
    if dnssec_validated:
        conf = min(conf + 0.02, 0.96)
    if ct_count > 0:
        conf = min(conf + 0.02, 0.96)
    # SSL deep "healthy" boost: modern TLS, strong cipher, SAN matches host,
    # not self-signed, not expired or about to expire.
    ssl_deep_healthy = (
        has_ssl
        and ssl_protocol_class == "modern"
        and ssl_cipher_class == "strong"
        and ssl_san_match is True
        and ssl_self_signed is False
        and ssl_expiry_status in ("ok", "warning")
    )
    if ssl_deep_healthy:
        conf = min(conf + 0.02, 0.96)

    # Tier-2 warnings
    if dnssec_checked and not dnssec_validated:
        warnings.append("no_dnssec_validation")
    if not spf_present:
        warnings.append("no_spf_record")
    if not dmarc_present:
        warnings.append("no_dmarc_record")
    elif dmarc_policy == "none":
        warnings.append("dmarc_policy_none_no_enforcement")
    if ct.get("checked") is False and ct.get("skipped_reason"):
        warnings.append(f"ct_log_unavailable:{ct.get('skipped_reason')}")
    if ct_count > 0:
        warnings.append(f"ct_revealed_{ct_count}_subdomains")

    # Tier-2 SSL deep warnings (only when SSL was actually inspected)
    if has_ssl:
        if ssl_expiry_status == "expired":
            warnings.append("ssl_certificate_expired")
        elif ssl_expiry_status == "critical":
            warnings.append(f"ssl_expires_in_{ssl_days_to_expiry}_days")
        elif ssl_expiry_status == "warning":
            warnings.append(f"ssl_expires_in_{ssl_days_to_expiry}_days_renew_soon")
        if ssl_protocol_class == "insecure":
            warnings.append("tls_insecure_protocol")
        elif ssl_protocol_class == "legacy":
            warnings.append("tls_legacy_protocol_consider_upgrade")
        if ssl_cipher_class == "weak":
            warnings.append("tls_weak_cipher")
        if ssl_san_match is False:
            warnings.append("ssl_san_mismatch_host_not_in_certificate")
        if ssl_self_signed is True:
            warnings.append("ssl_self_signed_certificate")

    # Mandatory honesty disclaimer — registrar / WHOIS data is often redacted
    warnings.append("registrar_data_may_be_privacy_redacted")

    answered = [
        label for label, hit in
        (("DNS", has_dns), ("RDAP", rdap_found), ("SSL", has_ssl),
         ("HTTP", http_reachable))
        if hit
    ]
    boosts = [
        label for label, hit in
        (("DNSSEC validated", dnssec_validated), ("CT log history", ct_count > 0),
         ("healthy TLS", ssl_deep_healthy))
        if hit
    ]
    reasoning: list[str] = [
        f"{successful} of 4 base sources answered"
        + (f" ({', '.join(answered)})." if answered else " - none of them.")
    ]
    if boosts:
        reasoning.append(
            f"Corroborated by {', '.join(boosts)} - hard-to-forge signals that "
            f"lift the confidence above the base ladder.")
    if ct_count > 0:
        reasoning.append(
            f"Certificate transparency exposed {ct_count} subdomain name(s).")
    if has_ssl and ssl_expiry_status in ("expired", "critical"):
        reasoning.append(
            f"Certificate is {ssl_expiry_status} ({ssl_days_to_expiry} days) - "
            f"the domain is authoritative but not well maintained.")
    reasoning.append(
        "Authoritative for the DOMAIN; registrar contact data is routinely redacted.")

    conf = _apply_context_cap(conf, context, warnings)

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="dns + rdap + ssl_deep + http + crt.sh + DoH DNSSEC + SPF/DMARC",
            source="local DNS + rdap.org + SSL handshake + HTTP GET + crt.sh + dns.google",
            warnings=warnings,
            errors=[],
            reasoning=reasoning[:5],
            extra={
                "dns_found": has_dns,
                "rdap_found": rdap_found,
                "ssl_valid": has_ssl,
                "http_reachable": http_reachable,
                "security_score": raw.get("security_score"),
                "dnssec_validated": dnssec_validated,
                "dnssec_checked": dnssec_checked,
                "spf_present": spf_present,
                "dmarc_present": dmarc_present,
                "dmarc_policy": dmarc.get("policy"),
                "ct_log_count": ct_count,
                "ct_log_cert_count": ct.get("cert_count") or 0,
                "ct_alive_count": ct_alive_count,
                "ct_log_checked": bool(ct.get("checked")),
                # Tier-2 SSL deep fields
                "ssl_protocol": ssl.get("protocol"),
                "ssl_protocol_class": ssl_protocol_class,
                "ssl_cipher_name": ssl_cipher_name,
                "ssl_cipher_bits": ssl_cipher_bits,
                "ssl_cipher_class": ssl_cipher_class,
                "ssl_expiry_status": ssl_expiry_status,
                "ssl_days_to_expiry": ssl_days_to_expiry,
                "ssl_san_match": ssl_san_match,
                "ssl_self_signed": ssl_self_signed,
                "ssl_sha256_fingerprint": ssl_fingerprint,
                "ssl_deep_healthy": ssl_deep_healthy,
                "context": context or "default",
            },
        ),
    )


def wrap_breach(raw: dict[str, Any]) -> dict[str, Any]:
    """Breach check: password HIBP is verified (k-anonymity), email HIBP
    requires a paid API key.
    """
    if not isinstance(raw, dict):
        raw = {}
    pw_check = raw.get("password_check") or {}
    em_check = raw.get("email_check") or {}

    warnings: list[str] = []
    errors: list[str] = []

    pw_ok = bool(pw_check.get("checked"))
    em_ok = bool(em_check.get("checked"))
    em_skipped = bool(em_check.get("skipped"))
    hibp_key = bool(os.environ.get("HIBP_API_KEY"))

    if not hibp_key and not em_check:
        warnings.append("hibp_api_key_missing_email_check_unavailable")

    # An email_check that was ATTEMPTED but neither succeeded nor was
    # cleanly skipped (e.g. a mid-request HIBP error/timeout) must not be
    # confused with "no email check requested at all" -- but it also must
    # not erase a genuinely verified password check. Both states fall
    # through to the same pw_ok branch below; the underlying error (if any)
    # is still surfaced rather than silently dropped.
    em_attempted_but_inconclusive = bool(em_check) and not em_ok and not em_skipped

    if pw_ok and em_ok:
        verdict, conf = VERIFIED, 0.97
    elif pw_ok and em_skipped:
        verdict, conf = VERIFIED, 0.88
        warnings.append("email_breach_skipped_no_hibp_key")
    elif pw_ok and (not em_check or em_attempted_but_inconclusive):
        verdict, conf = VERIFIED, 0.90
        if em_attempted_but_inconclusive and em_check.get("error"):
            errors.append(f"email_check_error: {em_check.get('error')}")
    elif em_ok and not pw_check:
        verdict, conf = VERIFIED, 0.93
    elif em_skipped and not pw_check:
        verdict, conf = UNVERIFIED, 0.15
        warnings.append("no_hibp_key_password_check_not_requested")
    elif not pw_ok and not em_ok:
        verdict, conf = UNVERIFIED, 0.10
        if pw_check.get("error"):
            errors.append(f"password_check_error: {pw_check.get('error')}")
        if em_check.get("error"):
            errors.append(f"email_check_error: {em_check.get('error')}")
    else:
        verdict, conf = INFERRED, 0.55

    reasoning: list[str] = []
    if pw_ok:
        reasoning.append(
            "The HIBP k-anonymity password check completed - a cryptographic "
            "range query, not a heuristic, which is why this wrapper may reach "
            "verified at all.")
    else:
        reasoning.append("No password check completed.")
    if em_ok:
        reasoning.append("The HIBP v3 email-breach lookup completed.")
    elif em_skipped:
        reasoning.append(
            "The email-breach lookup was skipped - that path needs a paid HIBP "
            "key, so its absence is a missing capability, not a clean result.")
    elif em_attempted_but_inconclusive:
        reasoning.append(
            "The email-breach lookup was attempted and did not conclude; it is "
            "treated as no email data rather than as a negative.")
    if not hibp_key:
        reasoning.append("No HIBP_API_KEY present in this environment.")

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="hibp_k_anonymity + hibp_v3_api",
            source="haveibeenpwned.com",
            warnings=warnings,
            errors=errors,
            reasoning=reasoning[:5],
            extra={
                "password_checked": pw_ok,
                "email_checked": em_ok,
                "email_skipped": em_skipped,
                "hibp_key_present": hibp_key,
            },
        ),
    )


def wrap_avatar(raw: dict[str, Any]) -> dict[str, Any]:
    """Avatar OSINT: real HTTP but 'profile picture exists' != 'owned by
    target'. Always at most inferred.
    """
    if not isinstance(raw, dict):
        raw = {}
    results = raw.get("results") or raw.get("platforms") or []
    found_any = False
    if isinstance(results, list):
        found_any = any(r.get("found") for r in results if isinstance(r, dict))
    elif isinstance(raw, dict):
        found_any = bool(raw.get("found") or raw.get("gravatar_found"))

    warnings = [
        "profile_image_existence_not_ownership",
        "avatar_correlation_is_probabilistic",
    ]
    if found_any:
        verdict, conf = INFERRED, 0.65
    else:
        verdict, conf = UNVERIFIED, 0.20
        warnings.append("no_avatars_matched")

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="gravatar_md5 + unavatar.io + direct_http",
            source="Gravatar + unavatar.io",
            warnings=warnings,
            errors=[],
            reasoning=[
                "A profile image was served for at least one identifier."
                if found_any else
                "No identifier returned a profile image.",
                "An image existing at an address says nothing about who owns "
                "it - correlation here is probabilistic, so the ceiling is inferred.",
            ],
            extra={"any_found": found_any},
        ),
    )


def wrap_company(raw: dict[str, Any]) -> dict[str, Any]:
    """Company OSINT: GitHub org is real API, social checks are 404-based."""
    if not isinstance(raw, dict):
        raw = {}
    github = raw.get("github", {}) or raw.get("github_org", {}) or {}
    gh_found = bool(github.get("found") or github.get("login"))

    warnings: list[str] = []
    errors: list[str] = []

    if gh_found:
        verdict, conf = INFERRED, 0.70
        warnings.append("github_verified_social_heuristic")
        reasoning = [
            "The GitHub org resolved through the real API - an authoritative hit.",
            "The social-presence half is still 404-scraped, so the weaker half "
            "sets the ceiling for the pair.",
        ]
    elif raw.get("domain"):
        verdict, conf = HEURISTIC, 0.40
        warnings.append("no_github_org_social_presence_inferred_from_404")
        reasoning = [
            "No GitHub org; only a domain was supplied.",
            "Everything left rests on 404-based social scraping, where false "
            "positives are expected.",
        ]
    else:
        verdict, conf = UNVERIFIED, 0.15
        warnings.append("no_data_sources_responded")
        reasoning = ["Neither a GitHub org nor a domain was available to check."]

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="github_api + http_404_scraping",
            source="api.github.com + social platforms",
            warnings=warnings,
            errors=errors,
            reasoning=reasoning,
            extra={"github_org_found": gh_found},
        ),
    )


def wrap_name(raw: dict[str, Any]) -> dict[str, Any]:
    """Name OSINT is a pure generator. No network calls."""
    if not isinstance(raw, dict):
        raw = {}
    return envelope(
        raw,
        build_trust(
            verdict=HEURISTIC,
            confidence=0.50,
            method="name_pattern_generator",
            source="local pattern tables",
            warnings=[
                "username_candidates_not_verified",
                "feed_to_username_scan_for_verification",
            ],
            reasoning=[
                "Nothing was looked up: this wrapper only expands a name into "
                "candidate handles from local pattern tables.",
                "The candidates are input for a scan, not findings - treating "
                "them as results would be inventing evidence.",
            ],
        ),
    )


def wrap_whois(raw: dict[str, Any]) -> dict[str, Any]:
    """WHOIS (RDAP) is real API."""
    if not isinstance(raw, dict):
        raw = {}
    found = bool(raw.get("found") or raw.get("registrar"))
    if found:
        return envelope(
            raw,
            build_trust(
                verdict=VERIFIED,
                confidence=0.93,
                method="rdap_http_api",
                source="rdap.org",
                reasoning=[
                    "RDAP answered over its real HTTP API - registry data, not "
                    "an inference.",
                    "Registrant contact fields are frequently privacy-redacted, "
                    "so 'authoritative' covers the registration, not the person.",
                ],
            ),
        )
    return envelope(
        raw,
        build_trust(
            verdict=UNVERIFIED,
            confidence=0.10,
            method="rdap_http_api",
            source="rdap.org",
            warnings=["rdap_lookup_failed"],
            reasoning=[
                "RDAP returned nothing usable - the honest state is 'no data', "
                "which is not evidence the domain is unregistered.",
            ],
        ),
    )


def wrap_ssl(raw: dict[str, Any]) -> dict[str, Any]:
    """SSL certificate inspection is real socket handshake."""
    if not isinstance(raw, dict):
        raw = {}
    has_ssl = bool(raw.get("has_ssl") or raw.get("certificate"))
    if has_ssl:
        return envelope(
            raw,
            build_trust(
                verdict=VERIFIED,
                confidence=0.96,
                method="ssl_socket_handshake",
                source="direct TLS handshake",
                reasoning=[
                    "A TLS handshake completed and the peer presented a "
                    "certificate - directly observed, not reported by a third "
                    "party.",
                    "The certificate is authoritative for what it attests; it "
                    "says nothing about who operates the host.",
                ],
            ),
        )
    return envelope(
        raw,
        build_trust(
            verdict=UNVERIFIED,
            confidence=0.08,
            method="ssl_socket_handshake",
            source="direct TLS handshake",
            warnings=["ssl_handshake_failed_or_no_cert"],
            reasoning=[
                "No handshake and no certificate - the host may be reachable "
                "without TLS, or not reachable at all; this cannot tell them apart.",
            ],
        ),
    )


def wrap_paste(raw: dict[str, Any]) -> dict[str, Any]:
    """Paste/leak search: GitHub API + grep.app real, Google scrape fragile."""
    if not isinstance(raw, dict):
        raw = {}
    hits = raw.get("results") or raw.get("hits") or []
    count = len(hits) if isinstance(hits, list) else 0

    warnings = ["relevance_not_guaranteed", "results_require_manual_review"]
    if count == 0:
        verdict, conf = UNVERIFIED, 0.20
        warnings.append("no_hits_in_any_source")
    elif count >= 5:
        verdict, conf = INFERRED, 0.70
    else:
        verdict, conf = INFERRED, 0.55

    reasoning = [
        f"{count} hit(s) across the paste/leak sources."
        if count else
        "No source returned a hit - absence here is weak, since these indexes "
        "are partial by nature.",
        "A string appearing in a paste is not attribution; every hit needs a "
        "human relevance call, which is why the ceiling is inferred.",
    ]

    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            confidence=conf,
            method="github_api + grep_app + google_scrape",
            source="GitHub + grep.app + Google",
            warnings=warnings,
            reasoning=reasoning,
            extra={"hit_count": count},
        ),
    )


def wrap_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    """Metadata extraction is local, deterministic, authoritative."""
    if not isinstance(raw, dict):
        raw = {}
    has_data = bool(raw) and not raw.get("error")
    if has_data:
        return envelope(
            raw,
            build_trust(
                verdict=VERIFIED,
                confidence=0.98,
                method="local_binary_parse",
                source="local filesystem",
                warnings=["exif_can_be_spoofed_or_stripped"],
                reasoning=[
                    "Parsed from the file on disk - deterministic, repeatable, "
                    "and dependent on no third party, which is why a local read "
                    "outranks every networked wrapper here.",
                    "Authoritative for what the file CLAIMS: EXIF can be edited "
                    "or stripped before the file ever reached you.",
                ],
            ),
        )
    return envelope(
        raw,
        build_trust(
            verdict=UNVERIFIED,
            confidence=0.10,
            method="local_binary_parse",
            source="local filesystem",
            errors=[raw.get("error", "no_metadata_extracted")] if raw.get("error") else [],
            reasoning=[
                "Nothing was extracted - either the format carries no metadata "
                "or it was stripped; this cannot distinguish the two.",
            ],
        ),
    )


def wrap_generic(
    raw: Any,
    *,
    verdict: str = UNVERIFIED,
    method: str = "unknown",
    source: str = "unknown",
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Fallback wrapper for endpoints without a dedicated trust mapping."""
    return envelope(
        raw,
        build_trust(
            verdict=verdict,
            method=method,
            source=source,
            warnings=warnings or [],
            reasoning=[
                f"No dedicated wrapper covers this source, so the verdict is "
                f"whatever the caller asserted ({verdict}) rather than anything "
                f"this package derived.",
            ],
        ),
    )


def wrap_pipeline(raw: dict[str, Any]) -> dict[str, Any]:
    """Unified pipeline aggregates multiple modules. Verdict is the WORST
    verdict across its sub-modules (a pipeline is only as trustworthy as
    its weakest link).
    """
    if not isinstance(raw, dict):
        raw = {}
    mods = raw.get("modules", {}) or {}
    # (name, verdict, confidence) per sub-module, in insertion order. The name
    # is carried because the aggregate verdict is meaningless without it: a
    # pipeline that reports `heuristic` tells the operator nothing actionable
    # unless it also says WHICH link was the weak one.
    sub_results: list[tuple[str, str, float]] = []
    unmapped: list[str] = []

    # Inspect each sub-module and compute a mini-verdict for it.
    for name, sub in mods.items():
        if not isinstance(sub, dict):
            continue
        if name == "username_scan":
            tb = wrap_username_scan(sub)["trust"]
        elif name == "email":
            tb = wrap_email(sub)["trust"]
        elif name == "phone":
            tb = wrap_phone(sub)["trust"]
        elif name == "ip":
            tb = wrap_ip(sub)["trust"]
        elif name == "domain":
            tb = wrap_domain(sub)["trust"]
        elif name == "breach":
            tb = wrap_breach(sub)["trust"]
        elif name == "avatar":
            tb = wrap_avatar(sub)["trust"]
        elif name == "company":
            tb = wrap_company(sub)["trust"]
        else:
            # No dispatch entry for this module name. The result is
            # `unverified`, which then drags the whole aggregate down -- and
            # before the reasoning below existed, it did so silently: the
            # operator saw an unverified pipeline with no way to tell that the
            # cause was an unrecognised NAME rather than a failed lookup.
            unmapped.append(str(name))
            tb = {"verdict": UNVERIFIED, "confidence": _CONF_ANCHOR[UNVERIFIED]}
        sub_results.append((str(name), tb["verdict"], tb["confidence"]))

    sub_verdicts = [v for _, v, _ in sub_results]

    weakest_module: str | None = None
    if not sub_verdicts:
        overall = UNVERIFIED
        conf = _CONF_ANCHOR[UNVERIFIED]
    else:
        # pick the lowest-trust verdict
        order = [UNVERIFIED, HEURISTIC, INFERRED, VERIFIED]
        lowest = min(sub_verdicts, key=lambda x: order.index(x) if x in order else 0)
        overall = lowest
        # Preserve real precision instead of collapsing to a static
        # per-verdict anchor: take the WEAKEST confidence among the
        # sub-modules that actually landed on the weakest tier. A pipeline
        # whose weak link is a strong 'inferred' (0.79) is meaningfully
        # more trustworthy than one whose weak link barely cleared
        # 'inferred' (0.56) -- both previously reported the same number.
        weakest = min(
            ((n, v, c) for n, v, c in sub_results if v == overall),
            key=lambda t: t[2],
        )
        weakest_module, conf = weakest[0], weakest[2]

    warnings = ["pipeline_verdict_equals_weakest_submodule"]
    if unmapped:
        warnings.append(f"pipeline_unmapped_modules:{','.join(sorted(unmapped))}")

    if weakest_module is None:
        reasoning = [
            "No sub-module produced a result, so the pipeline has nothing to "
            "aggregate - 'unverified' here means empty, not negative.",
        ]
    else:
        reasoning = [
            f"{len(sub_results)} sub-module(s) ran: "
            + ", ".join(f"{n}={v} {c}" for n, v, c in sub_results) + ".",
            f"'{weakest_module}' is the weak link at {overall} {conf} and sets "
            f"the aggregate - a chain is worth its weakest evidence, so "
            f"strengthening any other module will not move this number.",
        ]
        if unmapped:
            reasoning.append(
                f"{len(unmapped)} module name(s) have no dispatch entry "
                f"({', '.join(sorted(unmapped))}) and defaulted to unverified - "
                f"that is an unrecognised NAME, not a failed lookup."
            )

    return envelope(
        raw,
        build_trust(
            verdict=overall,
            confidence=conf,
            method="multi_module_pipeline",
            source="aggregated",
            warnings=warnings,
            reasoning=reasoning,
            extra={
                "sub_verdicts": sub_verdicts,
                "module_count": len(sub_verdicts),
                # Named breakdown: `sub_verdicts` keeps its historical shape
                # (a bare list) for existing consumers, but a bare list cannot
                # answer "which module was it".
                "sub_modules": [
                    {"module": n, "verdict": v, "confidence": c}
                    for n, v, c in sub_results
                ],
                "weakest_module": weakest_module,
            },
        ),
    )
