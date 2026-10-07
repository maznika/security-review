# Output Format

Phase 3 renders the deduped, tiered findings as a single Markdown document.

## Document structure

```
# Security Review — <scope>

<one-paragraph summary: N Tier-A findings, M Tier-B, K attack chains, lanes run, ASVS chapters touched>

**Where the findings are:** <N in application code · N in infrastructure · N in CI & dependencies · N design>. Omit surfaces with no findings.

> Lanes group related security standards. What each lane covers is described in
> [`references/discovery-lanes.md`](./discovery-lanes.md).

## Highest-leverage fix

<one line: the single remediation that breaks the most chains / resolves the most findings. Omit if no chains and ≤1 finding.>

## Tier A — High-confidence findings (score ≥ 7)

<per-finding block, see below — grouped by surface when more than one surface has findings>

## Tier B — Needs human review (score 4–6)

<terser per-finding block — title, file:line, surface, category, one-line why, score>

## Coverage report

<lane status table + ASVS chapters touched + Phase-0 scanners run/unavailable>

## Appendix — Attack chains

<brief explainer + Tier-A/B chain blocks from Phase 2.5, see below. Omit the section if none composed.>

## Run artifact

Full Phase-1 candidates, Phase-2 verdicts (including Tier C), and Phase-2.5 chains saved to
.security-review/<timestamp>/run.json
```

**Ordering is deliberate.** A developer opening this wants the fix list first. Attack chains explain how
findings *compose*, which is analysis rather than action — it belongs after the findings, referenced from
the summary and the highest-leverage fix rather than competing with them for the top of the page.

If Tier A is empty, say so explicitly:

> No high-confidence findings (Tier A). N items deferred to Tier B for human review.

## Surfaces

Every finding carries a **surface** — what kind of thing is broken, which decides who fixes it and what
approval the fix needs. Derived from the lane, per the index in
[discovery-lanes.md](./discovery-lanes.md#lane-index):

| Surface | Lanes | What it means for the reader |
|---|---|---|
| **Application code** | L01–L09, L12, L13 | Fix in the service's own source; normal code review |
| **Infrastructure** | L10 | Terraform / jsonnet / kube in the repo. IAM changes typically need a platform or security approval |
| **CI & dependencies** | L11 | Workflows, build config, third-party packages. Fixing may need repo-settings access rather than a code change |
| **Design** | L14 | An architectural concern, not a specific defect — usually a conversation, not a patch |

**Group by surface *within* a tier, never above it.** Severity ordering is what makes the report
actionable; promoting surface to a top-level split would bury a Critical CI finding under application-code
Lows. When a tier has findings on only one surface, omit the grouping headings entirely — a developer
reading a pure application-code report should not have to scroll past an empty taxonomy.

## Tier A finding block

````markdown
### A1 — Invoice fetch by ID does not check account ownership

- **File**: [app/invoices/views.py:142-148](app/invoices/views.py#L142-L148)
- **Severity**: High
- **Surface**: Application code · **Lane**: L03 — Authorization
- **Category**: `tenant_isolation` · ASVS V8.1.2 · CWE-639
- **Confidence**: 9/10

**Description.** View resolves `Invoice.objects.get(id=request.GET['id'])` without filtering by `request.user.account_id`, allowing IDOR across accounts.

**Evidence.**

```python
invoice = Invoice.objects.get(id=request.GET['id'])
```

**Attack path.** Authenticated user A enumerates invoice IDs and requests `/api/invoices/?id=<invoice_owned_by_B>`, receiving B's invoice JSON.

**Prerequisites.** Any authenticated session; knowledge of a target invoice id (4-byte int, enumerable).

**Recommendation.** Use `Invoice.objects.filter(id=..., account_id=request.user.account_id).first()` and 404 on miss. Add a regression test asserting cross-account access returns 404.
````

## Tier B finding block (terser)

```markdown
### B1 — Missing audit log on data export endpoint

- [app/exports/views.py:88](app/exports/views.py#L88) · Application code · `audit_log_policy_gap` · Low · 5/10

Export endpoint mutates state without calling the repository's audit-log helper, which its documented audit-log policy requires. Policy gap, not exploit.
```

## Attack chain block

Rendered under **`## Appendix — Attack chains`**, after the coverage report. Open the section with this
explainer so a reader meeting the idea for the first time knows what they are looking at:

> **Attack chains** link findings that are individually lower-impact but combine into a single higher-impact
> path — one finding's outcome becoming the next one's precondition. They are listed here as an appendix;
> the findings themselves are above, and fixing any one link breaks the chain.

Reference chains from the summary and the highest-leverage fix by ID (`CH1`), rather than restating them.

Rendered from the `chain` findings in [Chain Synthesis](./chain-synthesis.md). Show Tier-A and Tier-B chains; log Tier-C chains to the run artifact only.

````markdown
### CH1 — Cross-tenant invoice read via token audience confusion

- **Score**: 8/10 (Tier A) · **Objective**: read any tenant's invoice contents
- **Chain**: `L02-003` → `L03-007`
- **ATT&CK**: T1528 (steal application access token) → T1530 (data from cloud storage)

**Path.**

1. **`L02-003`** — invoice service accepts a JWT without checking `aud`. → *attacker mints a token the service accepts* (T1528)
2. **`L03-007`** — invoice fetch is unscoped by `account_id`; any valid token reads any invoice. → *cross-tenant read* (T1530)

Entry (`L02-003`) is reachable by any authenticated user; terminal impact is cross-tenant data access. Both hop endpoints are evidence-backed — no tier drop. Individually these were Tier B (5 and 6); composed they are Tier A.

**Residual prerequisites.** An authenticated session in any account.

**Break the chain.** Fixing either link severs it; **`L02-003` (add `aud` validation) is higher-leverage** — it also breaks CH3.
````

A **speculative** chain (a hop without a concrete postcondition→precondition match) is capped at Tier B and must name the missing link inline:

```markdown
### CH2 — (speculative) config write → RCE

- **Score**: 5/10 (Tier B, speculative) · **Chain**: `L07-004` → ⟨missing: a reachable code path that reloads the written config⟩

`L07-004` allows writing an unvalidated config value, but no finding demonstrates that value being executed or reloaded. Flagged for human review: confirm whether a reload path exists.
```

## Coverage report

```markdown
## Coverage report

| Lane                          | Surface | Status  | Files in scope | Findings | Notes                               |
| ----------------------------- | ------- | ------- | -------------: | -------: | ----------------------------------- |
| L01 — Injection               | App     | ran     |             12 |        0 | injection clean                     |
| L02 — Authentication          | App     | ran     |              3 |        1 | jwt aud check missing               |
| L03 — Authorization           | App     | ran     |             14 |        2 | both tenant-isolation               |
| L04 — Cryptography & secrets  | App     | ran     |              5 |        0 |                                     |
| L05 — Data exposure & logging | App     | ran     |             14 |        3 | 1 policy gap                        |
| L06 — Deserialization & RCE   | App     | skipped |              0 |        — | no deserialization sinks in scope   |
| L07 — Webapp (Django)         | App     | ran     |              9 |        0 |                                     |
| L08 — Frontend (web)          | App     | ran     |              6 |        0 |                                     |
| L09 — C/C++ memory safety     | App     | skipped |              0 |        — | no cpp files                        |
| L10 — IaC / IAM               | Infra   | skipped |              0 |        — | no iac files                        |
| L11 — Supply chain            | CI      | skipped |              0 |        — | no dependency manifests changed     |
| L12 — MCP tool boundary       | App     | skipped |              0 |        — | no mcp tool files                   |
| L13 — External connectors     | App     | skipped |              0 |        — | no connector files                  |
| L14 — Secure-by-design        | Design  | ran     |             14 |        1 | design concern: new public endpoint |

**ASVS chapters touched:** V1, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16.
**ASVS chapters not touched:** V2 — only L12 reaches it, and L12 was skipped.
**Not applicable:** V17 (WebRTC) — no lane covers it, and nothing in scope uses WebRTC.
Reviewer should confirm the not-touched list matches expectation.
```

The universe for these three lists is **V1–V17**, derived from the lane mapping in
[asvs-v5-chapters.md](./asvs-v5-chapters.md). Every chapter must appear in exactly one of them. A chapter
in none means the mapping and this report have diverged.

Statuses (`ran`, `ran (predicate gap)`, `n/a`, `skipped`, `failed`) are defined in [Analysis Methodology — Coverage statuses](./analysis-methodology.md#coverage-statuses).

## Severity guidelines

Severity is the finding's **impact**, and this table is the single source of truth for it. Five levels, each loosely aligned to a CVSS v3.1 score band so a rating can be converted to a number later if needed. In the JSON handoff these are the lowercase enum values `critical | high | medium | low | info`; the report renders them in Title case.

| Severity     | CVSS band | Criteria                                                                                                                    |
| ------------ | --------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Critical** | 9.0–10.0  | Trivially exploitable with severe blast radius — unauthenticated RCE, mass secret/data disclosure, or cross-tenant compromise reachable without privilege. |
| **High**     | 7.0–8.9   | Directly exploitable — RCE, auth bypass, cross-tenant data access, or privilege escalation, typically behind authentication or a modest precondition. |
| **Medium**   | 4.0–6.9   | Real impact, but only when specific conditions hold (a role, a feature flag, a non-default config).                        |
| **Low**      | 1.0–3.9   | Defense-in-depth gaps; policy gaps (audit-log missing on a sensitive endpoint); design concerns from L14.                  |
| **Info**     | 0.0–0.9   | Not a vulnerability by itself (e.g. a new dependency surfaced for SCA triage). Note anything recon-relevant in the finding's rationale so an interesting item sorts above a trivial one. |

Severity is independent of confidence score. A Tier-A finding (confidence ≥7) can still be `severity: low` if the impact is limited (e.g. an audit-log policy gap can be `low` severity at `9` confidence, even though policy gaps are typically Tier B since their reachability rarely lands above 6).

## Determinism notes for the synthesizer

- Sort Tier-A findings by `(severity desc, file asc, line_start asc)` then number `A1, A2, ...`.
- Sort Tier-B findings the same way, number `B1, B2, ...`.
- Sort chains by `(score desc, entry_finding_id asc)` then number `CH1, CH2, ...`. Because component finding IDs are themselves deterministic, chain composition and ordering are reproducible across runs.
- Two runs of the same PR with the same inventory must produce identical finding IDs, identical chains, and identical ordering. Any drift is a synthesizer bug, not a model bug.
