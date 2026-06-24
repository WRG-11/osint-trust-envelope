# osint-trust-envelope

[![CI](https://github.com/WRG-11/osint-trust-envelope/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WRG-11/osint-trust-envelope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/WRG-11/osint-trust-envelope/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/WRG-11/osint-trust-envelope/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/WRG-11/osint-trust-envelope)](https://github.com/WRG-11/osint-trust-envelope/blob/main/LICENSE)

**Per-source-type epistemic ceilings for OSINT results - anti-overclaim as code.**

## Status

Experimental — feature-complete and CI-tested with a zero-dependency core, but not yet published to PyPI, and the confidence anchors are hand-calibrated tradecraft heuristics rather than corpus-validated metrics (see [What this is not](#what-this-is-not)).

OSINT tooling loves to render a green checkmark. A username "found" on 40 sites,
a phone number "traced" to a carrier, an email "confirmed" - all presented with
the same confident UI as a cryptographically real breach hit. The problem is
that most OSINT signals *cannot* support that confidence, and the uncertainty
usually lives only in a human analyst's head (or a footnote nobody reads).

This package moves that uncertainty into the type system of the result. Every
lookup is wrapped in a `{"result": ..., "trust": ...}` envelope whose **verdict
is capped at the highest level the source _type_ can honestly support** - and
that cap is written into the code, not left to caller discipline.

```python
from osint_trust_envelope import wrap_phone

env = wrap_phone({
    "parsed": {"valid": True, "country_code": "+1", "enrichment_source": "libphonenumber"},
    "social_checks": [{"platform": "WhatsApp", "possible": True}],
})

env["trust"]["verdict"]      # -> "inferred"   (never "verified", by design)
env["trust"]["confidence"]   # -> 0.66
env["trust"]["warnings"]     # -> ["number_portability_not_reflected",
                             #     "ownership_not_determinable_from_number_alone", ...]
```

A phone number wrapper structurally **cannot** return `verified`, no matter how
rich the input. That is the whole point.

---

## The verdict ladder

Four levels, most trustworthy to least:

| Verdict | Meaning | Confidence band |
| --- | --- | --- |
| `verified` | A real, authoritative source confirmed it (HIBP k-anonymity, an RDAP/DNS resolve, EXIF parsed from a local file). | 0.85 - 1.00 |
| `inferred` | Real data was retrieved, but the interpretation is indirect (an MX record exists; an avatar URL returned 200). | 0.55 - 0.80 |
| `heuristic` | Pattern/regex/404-scraping. False positives are expected. | 0.25 - 0.55 |
| `unverified` | The check was attempted but nothing came back, or the input was malformed. The honest "we don't know". | 0.00 - 0.20 |

`confidence` is a separate 0-1 number that tracks the verdict but lets you
order results *within* a band.

> Note on the word **`verified`**: it is a verdict *label* meaning "an
> authoritative upstream source confirmed this", assigned from the raw data you
> pass in. The library performs no network calls and makes no independent claim
> about your data - it records the ceiling the source type allows.

---

## Per-source ceilings (and why they exist)

This table is the library. Each wrapper enforces a maximum verdict because of a
concrete tradecraft reason the source type can't escape.

| Wrapper | Max verdict | Why it can't go higher |
| --- | --- | --- |
| `wrap_phone` | **inferred** | Number portability (MNP) breaks prefix-to-carrier inference; messenger presence proves *reachability*, not ownership; a paid reverse-lookup gives a *current* carrier, never an identity. |
| `wrap_email` | **inferred** | An MX record proves the domain accepts mail, not that *this* mailbox exists or is read; aliases, forwarders and catch-all rules are invisible from outside; SPF/DMARC describe handling policy, not ownership. |
| `wrap_username_scan` | **heuristic** (-> inferred with cross-platform corroboration, historical track record, or zero hits across N responsive sites) | HTTP-status / 404-based detection is structurally fragile - false positives are expected. Cross-platform agreement or a per-site reliability history earns a promotion. Zero hits across N sites that *responded* is a strong negative and yields `inferred 0.60`. |
| `wrap_company` | **inferred** | A GitHub org is a real API hit, but the social-presence half is 404-scraped. |
| `wrap_avatar` | **inferred** | "A profile image exists at this URL" is not "owned by the target"; correlation is probabilistic. |
| `wrap_paste` | **inferred** | Hits require manual relevance review; the presence of a string is not attribution. |
| `wrap_ip` | **verified** (<= 0.92; <= 0.95 for a Tor exit) | Geo + RDAP + reverse-DNS can corroborate each other, but geolocation is ISP-level, never user-level. |
| `wrap_domain` | **verified** (<= 0.96) | DNS + RDAP + SSL + HTTP are authoritative *for the domain*; registrar/WHOIS data is frequently privacy-redacted. |
| `wrap_breach` | **verified** (<= 0.97) | The HIBP k-anonymity password check is cryptographically real; the email-breach path needs a paid key. |
| `wrap_whois` / `wrap_ssl` / `wrap_metadata` | **verified** | RDAP API, a TLS handshake, and a local binary parse are authoritative for what they measure (EXIF can still be spoofed or stripped). |
| `wrap_pipeline` | **= weakest sub-module** | A pipeline is only as trustworthy as its least-trustworthy link. |

Mandatory honesty disclaimers ride along in `trust.warnings` and are always
present for the relevant source type - e.g. a phone result always carries
`number_portability_not_reflected`; an email always carries
`mailbox_existence_not_proven`; an IP always carries
`ip_geolocation_is_isp_level_not_user_level`. They cannot be configured off.

---

## What this is **not**

Being honest about the tool is the same discipline the tool encodes:

- **The confidence anchors and ceilings are hand-calibrated tradecraft
  heuristics, not measured precision/recall.** They have **not** been validated
  against a labelled external corpus. The numbers express a *relative epistemic
  ordering* ("an MX record is worth more than a regex match, less than a DNSSEC
  resolve"), not a probability you should bet on. No accuracy figure is claimed.
- **It performs no lookups.** It does not call any API, resolve any DNS, or
  touch the network. You bring the raw result from your own adapters; this
  layer only assigns the trust envelope.
- **It does not make a person-level identity determination.** Every wrapper
  that touches identity caps below `verified` precisely because identity cannot
  be established from these signals.

If you wire this into a product, surface the verdict and the warnings - not a
bare green checkmark.

---

## Used by

### `wrg_project_osint` — token-project OSINT aggregator

[WinstonRedGuard monorepo](https://github.com/WRG-11) uses this library to
wrap [maigret](https://github.com/soxoj/maigret) username-scan results and
RDAP domain-age lookups before surfacing them to the CLI and cockpit.

The integration produced two concrete observations:

**Zero hits across N responsive sites is a strong negative (`inferred`, not `unverified`)**

When a scanner checks 100 sites and finds zero hits, and those sites all
responded cleanly, that is evidence of absence — not missing data. The library
returns `inferred 0.60`:

```python
from osint_trust_envelope import wrap_username_scan

env = wrap_username_scan({
    "sites_checked": 100,
    "sites_found": 0,
    "results": [{"status": "not_found"}] * 100,
})
env["trust"]["verdict"]     # "inferred"   (100 sites responded; absence is evidence)
env["trust"]["confidence"]  # 0.60
```

If the scanner could not run at all (binary missing, subprocess timeout),
signal adapter failure with `sites_checked=0` and an empty results list.
This yields `unverified` — the honest "no data" state, distinct from a
negative signal:

```python
env = wrap_username_scan({"sites_checked": 0, "sites_found": 0, "results": []})
env["trust"]["verdict"]     # "unverified"  (no data collected)
```

**RDAP-only domain lookup yields `inferred`, not `verified`**

A keyless RDAP lookup gives one of four authoritative signals (DNS, RDAP,
SSL, HTTP). One signal is enough for `inferred 0.55` but not `verified`:

```python
from osint_trust_envelope import wrap_domain

env = wrap_domain({
    "rdap": {"found": True},
    "dns": {},
    "ssl": {"has_ssl": False},
    "http": {"reachable": False},
})
env["trust"]["verdict"]    # "inferred"   (one source; not verified)
env["trust"]["confidence"] # 0.55
env["trust"]["warnings"]   # ["only_one_source_responded", ...]
```

---

## Optional: historical per-site enrichment

`wrap_username_scan` can lift a verdict from `heuristic` toward `inferred` when
it has a *historical reliability score* per site. That data source is a
pluggable seam, **not bundled** (the core stays zero-dependency):

```python
import osint_trust_envelope.trust as trust

# username -> {site: reliability_score 0..1}
def my_history(username: str) -> dict[str, float]:
    return load_scores_for(username)

trust._get_site_confidences = my_history
# optional: trust._detect_site_anomaly = my_anomaly_detector
```

The shipped defaults are no-ops, so out of the box the scanner uses only the
static ladder. Wiring a provider is entirely opt-in.

---

## Install

```bash
pip install osint-trust-envelope        # once published
# or, from a checkout:
pip install .
```

Zero runtime dependencies. Python 3.10+.

## Run the demo

```bash
python demo.py
```

## Run the tests

```bash
pip install ".[dev]"
pytest
```

---

## License

MIT - see [LICENSE](LICENSE).

---

## Part of the WRG-11 ecosystem

- [mcp-objauthz-lab](https://github.com/WRG-11/mcp-objauthz-lab) — vulnerable-by-design MCP server for learning BOLA/IDOR
- [devguard-scan](https://github.com/WRG-11/devguard-scan) — 100% client-side secret scanner

Full index → [github.com/WRG-11](https://github.com/WRG-11)
