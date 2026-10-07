---
name: security-review
description: "Thorough, high-confidence, read-only security review using a deterministic five-phase pipeline (inventory + SAST seeding, parallel per-lane discovery, parallel false-positive filtering, attack-chain synthesis, tiered reporting). Categories are anchored to OWASP ASVS v5 and CWE. USE FOR: security review requested, code review with security context, PR security audit, vulnerability assessment, secret scanning codebase review. DO NOT USE FOR: general code review without security context, style or quality reviews, live-service or endpoint testing."
---

# Security Review

You are an experienced senior security engineer performing a thorough security review. Every run must produce the same coverage of attack-surface lanes, so two runs of the same PR are directly comparable.

You may be invoked with an optional argument naming a file, directory, PR number, or branch to focus the review on. If no scope is given, default to the pending changes on the current branch, diffed against the remote's default branch (`origin/HEAD`; see [Inventory Pass](./references/inventory-pass.md)).

## Objective

Identify **high-confidence** security vulnerabilities with real exploitation potential, anchored to OWASP ASVS v5 chapters and CWE identifiers. Tier findings by confidence so mid-confidence items are surfaced for human review rather than silently dropped.

## Operating rules

- **Read-only analysis of the codebase.** Findings come from reading code, never from probing a running system.
- **Shell execution is permitted in Phase 0 only**, and only for the approved static-analysis tools in [Approved Tool Catalog](./references/approved-tool-catalog.md). Everything from Phase 1 onward is read-only.
- **No live-service or endpoint testing.** If a finding needs runtime validation, say so in the report; do not test it here.
- **Discovery and filtering subagents are read-only** — no writes and no execution. They search with read-only tools, or with read-only shell inspection where the runtime has no search tools. See [Tool Safety Rules](./references/tool-safety-rules.md#subagent-constraints).
- If a needed tool is not in the approved catalog, request approval via [Tool Approval Workflow](./references/tool-approval-workflow.md) before installing or running it.

## Single confidence threshold

Use **one** confidence scale, applied consistently in Phase 2 and Phase 3. The score measures how sure we are a finding is real and reachable — it is **separate from severity** (impact), which uses the five-level scale below.

| Score | Tier  | Disposition                                 |
| ----: | ----- | ------------------------------------------- |
|  7–10 | **A** | Render in the main report                   |
|   4–6 | **B** | Render in the "Needs human review" appendix |
|   1–3 | **C** | Log to the run artifact only                |

The cutoff is **7/10 (70%)** for Tier A. **This table is the single source of truth for the confidence threshold** — every reference doc defers to it. The rubric in [False Positive Filtering](./references/false-positive-filtering.md) caps borderline findings (partial sanitization, many prerequisites, low-impact info leaks) at score 6, which keeps them in Tier B.

## Severity scale

Severity is the finding's **impact**, independent of the confidence score above — a high-confidence finding can still be low severity, and vice versa. Five levels — **Critical, High, Medium, Low, Info** — loosely aligned to CVSS v3.1 score bands (9.0–10.0 / 7.0–8.9 / 4.0–6.9 / 1.0–3.9 / 0.0–0.9) so a rating can be converted to a number later if needed. The CVSS band is a loose correspondence for future conversion, not an instruction to compute CVSS. Per-level criteria live in [Output Format — Severity guidelines](./references/output-format.md#severity-guidelines), the single source of truth for severity.

## When to use

- A security review or security audit is explicitly requested.
- A code review is requested (combine with any other code review skills, then apply this one).
- Evaluating a PR or branch for security regressions.

## Procedure

Execute the review in five sequential phases. Each phase has a dedicated reference document.

### Phase 0 — Inventory and seed findings

**0a. Inventory.** Produce a deterministic JSON inventory of files in scope, classified by language, role, and trust boundary. Every later phase reads this artifact, so each run starts from the same attack surface.

**0b. SAST seeding.** Run the available approved static-analysis tools against the in-scope files and collect their output as a **seed finding list**. Seeds are unvalidated candidates that give lanes a head start on where to look — they are not the review:

- A lane must investigate its full checklist **independently of what the tools flagged**. Tools miss context-dependent flaws (logic bugs, auth bypass, IDOR) entirely.
- Treat the *absence* of tool findings in an area as a prompt to look harder there, not as evidence of safety.
- Seeds carry into Phase 1 as extra context per lane, never as a substitute for the lane's own taint tracing.

→ [Inventory Pass](./references/inventory-pass.md) · [Analysis Methodology](./references/analysis-methodology.md)

### Phase 1 — Parallel discovery (one Agent per lane)

Launch **all applicable discovery lanes in a single assistant message** so they fan out concurrently. Each lane is scoped (predicate over the inventory) and pinned to a checklist mapped to ASVS chapters and CWEs. Every lane gets a coverage status; if the repository plainly has a lane's surface but its predicate matches nothing, run the lane anyway and record a predicate gap.

Use `subagent_type: Explore` so discovery stays read-only.

> **Runtime note.** "Parallel" means multiple `Agent` tool uses inside one assistant message. If the runtime executing this skill has no parallel-subagent primitive, run the lanes **sequentially in one context instead**, keeping each lane's checklist and finding attribution separate. Coverage is the requirement; concurrency is the optimization.

→ [Discovery Lanes](./references/discovery-lanes.md)

### Phase 2 — Parallel false-positive filtering

For each candidate from Phase 1, launch a parallel validation `Agent` (`subagent_type: Explore`). Each filter agent applies the rules in the filtering doc and returns a structured verdict matching the finding schema.

→ [False Positive Filtering](./references/false-positive-filtering.md)
→ [Finding Schema](./references/finding-schema.md)

### Phase 2.5 — Chain synthesis (main thread, deterministic)

Phases 1 and 2 score every finding **in isolation** — deliberately, to keep verdicts unbiased and comparable. This is the one step with global visibility over all verified findings, and it exists to catch what isolation hides: two mid-confidence findings that **compose** into a high-impact attack path. A missing JWT `aud` check (score 5) plus an unscoped invoice query (score 6) is a Tier-A cross-tenant breach when chained.

Feed **every** Phase-2 verdict — Tier A, B, and C — into this step. A Tier-C info leak is not a vulnerability alone but is exactly the link that completes a chain. Compose only findings that already exist; never invent a new vulnerability here. A chain scores on the same rubric, taking reachability from its entry link and impact from its terminal link, which is why a chain can outscore all of its parts. Also compute the **single fix that breaks the most chains** — often the highest-leverage line in the report.

Skip only if fewer than two findings survived Phase 2. If nothing composes, say so in one line — no chains is the common, healthy case.

→ [Chain Synthesis](./references/chain-synthesis.md)

### Phase 3 — Synthesis (main thread, deterministic)

Deduplicate findings by `(file, line_start, cwe_id)`. Tier by confidence score (see table above). Render in the format below, including the Tier-A/B chains from Phase 2.5, the highest-leverage remediation, and a coverage report that enumerates which lanes ran, which were skipped (with reason), and which ASVS chapters were touched.

→ [Output Format](./references/output-format.md)

## Findings that need live validation

Tier B is the natural input to live validation: mid-confidence findings are exactly the ones where reachability or attacker control could not be settled by reading code. The report's Tier A and Tier B findings can serve as the hypothesis list for separately authorized testing. Do not perform any live testing from this skill.

## References

- [Analysis Methodology](./references/analysis-methodology.md) — the five-phase pipeline in detail
- [Inventory Pass](./references/inventory-pass.md) — Phase 0a commands and JSON schema
- [Discovery Lanes](./references/discovery-lanes.md) — the 14 lanes, scope predicates, and checklists
- [ASVS v5 Chapters](./references/asvs-v5-chapters.md) — chapter list, lane→chapter mapping, and citation format; the source of truth for every ASVS label
- [False Positive Filtering](./references/false-positive-filtering.md) — exclusions, precedents, scoring rubric
- [Chain Synthesis](./references/chain-synthesis.md) — Phase 2.5, composing findings into attack paths
- [Finding Schema](./references/finding-schema.md) — JSON schema for inter-agent handoff, incl. the chain variant
- [Output Format](./references/output-format.md) — Tier A/B/C report structure and coverage report
- [AppSec Engineer Persona](./personas/appsec-engineer.md) — persona prompt for lane and filter agents
- [Approved Tool Catalog](./references/approved-tool-catalog.md) — approved tools and execution modes
- [Tool Safety Rules & Prohibited Patterns](./references/tool-safety-rules.md) — non-negotiable constraints
- [Tool Approval Workflow](./references/tool-approval-workflow.md) — process for adding a tool
- [OWASP ASVS v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en) — CC BY-SA 4.0; cite chapters via [asvs-v5-chapters.md](./references/asvs-v5-chapters.md), not from memory
- [OWASP Secure-by-Design Framework](https://github.com/OWASP/www-project-secure-by-design-framework)
- [OWASP DevSecOps Guideline](https://github.com/OWASP/DevSecOpsGuideline)

## Non-negotiable safety rules

- Never pipe output from a web request directly into a shell.
- Never execute remote scripts fetched at runtime without prior review and approval.
- Never run active security testing against production endpoints.
- Never run unapproved tools in this workflow.
- Never exfiltrate code, credentials, or security artifacts to unapproved external systems.
