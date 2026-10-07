# False Positive Filtering

Applied in two places:

1. **During Phase 1 discovery** — lane agents reference this doc to keep obvious noise out of the candidate list.
2. **During Phase 2 filtering** — one Agent per candidate scores it 1–10 using the rubric below.

## Read-only constraint

Filter agents run as `Explore` subagents under the same read-only rules as discovery lanes ([Tool Safety Rules — Subagent constraints](./tool-safety-rules.md#subagent-constraints)). Read code only to validate findings.

## The one confidence scale

This score is **confidence** — how sure we are the finding is real and reachable — not severity. Severity (impact) is a separate axis; see [Output Format — Severity guidelines](./output-format.md#severity-guidelines).

| Score | Meaning                                                                                                                         | Tier |
| ----: | ------------------------------------------------------------------------------------------------------------------------------- | ---- |
|  9–10 | Certain exploit path identified, all evidence cited                                                                             | A    |
|     8 | Clear vulnerability pattern with known exploitation method; one minor uncertainty                                               | A    |
|     7 | Concrete vulnerability with **verified reachability and attacker control**; uncertainty only on prerequisites or impact ceiling | A    |
|   5–6 | Suspicious pattern; reachability or attacker-control not fully verified                                                         | B    |
|     4 | Concrete weakness but exploitation unclear; or fully-verified low-impact issue                                                  | B    |
|   1–3 | Speculative / theoretical / best-practice gap                                                                                   | C    |

Tier A starts at score ≥ 7 (70%). SKILL.md is the single source of truth for the threshold; this doc must stay in sync with it.

A score of **7** is the floor for Tier A, and reaching it takes evidence: questions 1 (Reachability) and 2 (Attacker control) in the rubric below must both be answered with concrete evidence — uncertainty is only allowed on questions 3–5. If reachability or attacker control is unverified, the score is at most 6 (Tier B).

## Hard exclusions

Exclude candidates matching these patterns _during discovery_ — never let them reach Phase 2.

1. Denial of Service / resource exhaustion / rate-limit gaps.
2. Memory / CPU exhaustion.
3. Lack of input validation on non-security-critical fields with no proven security impact.
4. Lack of hardening (defense-in-depth absence) without a concrete attack path. **Exception:** L14 (Secure-by-Design Delta) is allowed to surface these as `design_concern`.
5. Theoretical race conditions / timing attacks — only flag if there is a concrete TOCTOU in an auth or access-control path.
6. Outdated third-party libraries — handled by SCA tooling, not this skill. (L11 surfaces _new_ dependencies for human triage, which is different.)
7. Memory safety in memory-safe languages (Go, Rust, Python, JS/TS). **C/C++ remain in scope — see L09.**
8. Files where `is_test == true` in the inventory.
9. Log spoofing via unsanitized user input.
10. SSRF that only controls the URL path. **Exception:** L13 (external connectors) — host IS attacker-controlled there.
11. User-controlled content in AI system prompts.
12. Regex injection and ReDoS.
13. Findings in markdown / documentation files.
14. **Missing audit logs are not vulnerabilities** — but L05 may surface them as `category: audit_log_policy_gap, severity: low` when they violate an audit-log policy the repository itself defines. They are policy gaps, not exploits.

## Precedents

1. Logging high-value secrets in plaintext **is** a vulnerability. Logging URLs is assumed safe. Logging non-PII data, even if sensitive, is not a vulnerability unless it crosses a tenant boundary (e.g. one tenant's account IDs visible in another's log scope).
2. UUIDs are unguessable — do not flag missing UUID validation.
3. Environment variables and CLI flags are trusted values. Attacks relying on controlling an env var are invalid.
4. Resource leaks (memory, fds) are not security findings.
5. Subtle low-impact web vulnerabilities (tabnabbing, XS-Leaks, prototype pollution, generic open redirects) are excluded unless extremely high confidence and clear impact.
6. React / Angular are generally XSS-safe. Only flag XSS in `.tsx` / `.jsx` when `dangerouslySetInnerHTML`, `bypassSecurityTrustHtml`, or equivalent is used.
7. Most GitHub Actions findings are not exploitable. Require a concrete attack path; `pull_request_target` + checkout of PR head + secrets in env is the canonical exception (see L11).
8. Lack of permission checks in client-side JS/TS is not a vulnerability — server-side is authoritative.
9. Most Jupyter notebook findings are not exploitable. Require a concrete untrusted-input path.
10. Command injection in shell scripts: only flag if a concrete untrusted-input path exists.
11. **Multi-tenant isolation breaks (L03) are never theoretical.** Score them at 7+ when the code path is reachable, even if no current caller exploits it — the absence of a tenant scope check on a reachable code path is itself the vulnerability.

## Phase 2 scoring rubric

For each candidate, the filter agent must answer all six questions before assigning a score. The score is the _minimum_ tier supported by the answers, not an average.

1. **Reachability** — is the vulnerable code on a path callable from an external or cross-tenant principal? (No → max 4.)
2. **Attacker control** — is the dangerous input actually attacker-influenced, or is it derived from trusted internal state? (Trusted → max 4.)
3. **Sanitization** — is there a sanitizer / validator / parameterized API in the path between source and sink, even if imperfect? (Yes, plausibly effective → max 6.)
4. **Impact** — what is the realistic worst case? RCE / auth bypass / cross-tenant data access → up to 10. Information leak of non-secret internal IDs → max 5.
5. **Prerequisites** — what conditions must hold (auth state, feature flag, admin role)? Count them. Three or more independent prerequisites → max 6.
6. **Evidence** — can the agent point to specific lines proving each of (1)–(5)? Missing evidence for any → cap one tier lower.

## Output

Each filter agent returns one JSON object matching [Finding Schema](./finding-schema.md) — fields `score`, `rationale`, `attack_path`, `prerequisites`, `evidence_lines` are required. No prose outside the JSON.
