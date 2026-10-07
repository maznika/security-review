# OWASP ASVS v5.0 — chapter reference

The authoritative chapter list for every ASVS citation in these skills. **Cite from this file rather than
from memory or a web fetch** — it exists so that every run produces the same chapter numbers and titles,
and so a wrong label shows up as a diff rather than drifting unnoticed.

> **License note:** This file includes ASVS-derived content and is licensed under
> [Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).

> **Version:** ASVS **v5.0.0** · retrieved **2026-10-07** from
> <https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en>
>
> **Attribution:** The OWASP Application Security Verification Standard is © OWASP Foundation, licensed
> under [Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).
> Chapter numbers and titles below are reproduced from ASVS v5.0.0 under that license. This file is an
> index of chapter names plus our own lane mapping; it does not reproduce requirement text.

## The 17 chapters

v5.0 restructured the standard — **the numbering is not compatible with v4.x.** Several v4 chapter names
survive at different numbers, so a stale label lands on a real-but-wrong chapter. Treat any chapter title
not in this table as a bug.

| # | Chapter | Frequently cited sections |
|---|---|---|
| V1 | Encoding & Sanitization | V1.3.6 SSRF · V1.5 Safe Deserialization |
| V2 | Validation & Business Logic | |
| V3 | Web Frontend Security | V3.5 CSRF |
| V4 | API & Web Service | |
| V5 | File Handling | |
| V6 | Authentication | |
| V7 | Session Management | |
| V8 | Authorization | V8.2.3 field-level access |
| V9 | Self-contained Tokens | |
| V10 | OAuth & OIDC | |
| V11 | Cryptography | |
| V12 | Secure Communication | |
| V13 | Configuration | V13.3 Secret Management |
| V14 | Data Protection | |
| V15 | Secure Coding & Architecture | V15.2 Dependencies · V15.3.3 mass assignment |
| V16 | Security Logging & Error Handling | |
| V17 | WebRTC | |

### Common mislabels

Each of these resolves to a real chapter and so reads as plausible. Check new citations against this list:

| Wrong label | Where it came from | Correct |
|---|---|---|
| V8 "Access Control" | v4 terminology | V8 **Authorization** |
| V12 "Secret Management" | not an ASVS chapter in any version | V12 **Secure Communication**; secrets are **V13.3** |
| V13 "Communication" | v5's V12, off by one | V13 **Configuration** |
| V14 "Configuration & Logging" | v4's V14 (Configuration) | V14 **Data Protection**; logging is **V16** |
| V10 for deserialization | v4's V10 (Malicious Code) | V10 is **OAuth & OIDC**; deserialization is **V1.5** / V15 |

## Citing a requirement

Cite as `V<chapter>.<section>.<requirement>` — e.g. `V8.1.2`. When the exact requirement is unclear, cite
the section (`V10.2`) rather than guessing a requirement number.

The version is pinned **once, here** (v5.0.0) rather than repeated on every ID. That keeps citations
readable while still being unambiguous, since every ASVS ID in these skills resolves against the version
stamped above. If the pinned version changes, every existing citation must be re-verified — see
*Refreshing this file*.

**Verify before citing a specific requirement.** This file pins chapters and the sections we lean on; a
plausible-looking requirement number is not evidence that the requirement exists. Never invent one.

## Lane → chapter mapping

The authoritative mapping for [discovery-lanes.md](./discovery-lanes.md). Each lane's chapters follow
from what its checklist actually inspects.

| Lane | Chapters |
|---|---|
| L01 Injection | V1, V5 |
| L02 Authn / session / tokens | V6, V7, V9, V10 |
| L03 Authorization & multi-tenant | V8 |
| L04 Cryptography, secrets, communication | V11, V12, V13 (V13.3), V16 |
| L05 Data exposure & logging | V14, V16 |
| L06 Deserialization & RCE | V1 (V1.5), V15 |
| L07 Webapp (Django) | V1, V3 (V3.5), V4, V5, V8 (V8.2.3), V13, V15 (V15.3.3) |
| L08 Frontend (web) | V1, V3 |
| L09 C/C++ memory safety | — |
| L10 IaC / IAM | V13 |
| L11 Supply chain | V13, V15 (V15.2) |
| L12 MCP tool boundary | V1, V2, V4, V8 |
| L13 External connectors | V1 (V1.3.6), V12, V13 (V13.3), V16 |
| L14 Secure-by-design delta | — |

**L09 and L14 are legitimately `N/A`.** ASVS is an application-verification standard: it has no
memory-safety chapter (L09), and L14 is an architectural lens rather than a control checklist. These are
the only two lanes permitted `asvs_id: N/A` — see [finding-schema.md](./finding-schema.md).

**V17 (WebRTC) is reachable by no lane.** For most codebases that is a property of the code, not a coverage
gap — report it as *not applicable* rather than untouched. If the scope does use WebRTC (`RTCPeerConnection`,
`getUserMedia`, TURN/STUN or SFU configuration), report V17 as *not touched* and say why in the coverage notes.

**V2 is reachable only by L12.** Worth knowing when reading a coverage report: if the MCP lane is skipped,
V2 shows as untouched even on a thorough review.

## Coverage reporting

The coverage report enumerates chapters **touched**, **not touched**, and **not applicable**, and the
universe for that enumeration is **V1–V17** — all seventeen. Every chapter must land in exactly one of the three lists; a chapter missing from all three
leaves the report silently blind to it. If you change the lane mapping above, re-derive all three from it rather
than editing the example by hand.

## Refreshing this file

On a new ASVS release:

1. Re-read the chapter list from the OWASP repo at the new tag; update the table and the version stamp.
2. Re-derive the lane mapping — v5 renumbered wholesale, so assume a future release may too.
3. Re-verify every cited section and requirement; the version pin above covers them all at once, so a
   bump invalidates all of them at once.
4. Update the coverage universe if the chapter count changed.
5. Grep for stale citations: `grep -rn "ASVS\|asvs_id" .` from the skill directory.
6. Keep the common-mislabels list and add any new mislabel you find.
