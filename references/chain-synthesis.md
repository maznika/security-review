# Chain Synthesis (Phase 2.5)

Phases 1 and 2 find and score vulnerabilities **in isolation** — by design. Lane agents never see each other's files; filter agents never see each other's verdicts, so anchoring bias can't inflate scores. That independence is what makes runs comparable, but it has a blind spot: **two findings that are individually mid-confidence can compose into a high-confidence breach that no single agent is positioned to see.**

A JWT missing its `aud` check might score 5 (reachability unproven). An invoice fetch unscoped by `account_id` might score 6 (needs a valid token). Each lands in Tier B, filed for human review. Chained — forge a token the wrong service accepts, then read another tenant's data — they are a Tier A cross-tenant breach.

Phase 2.5 is the one step in the pipeline with **global visibility over every verified finding**. It runs on the main thread, after all Phase-2 verdicts are in and before Phase 3 synthesis. It is the static-review analogue of a red-team chain-synthesis pass.

## Hard constraints

1. **Compose, never invent.** Chain synthesis may only connect findings that Phase 2 already produced — including Tier C. It must not introduce a vulnerability that no lane independently found. If a chain needs a hop that no finding provides, the chain is **speculative**: cap it at Tier B, name the missing link explicitly, and flag it for human review. This keeps every chain traceable to already-verified evidence and keeps runs deterministic.
2. **Read-only.** This phase reasons over the Phase-1/Phase-2 artifacts and may re-read cited code to confirm a hop. Read-only search and inspection only ([Tool Safety Rules](./tool-safety-rules.md#subagent-constraints)); no execution, no writes.
3. **One confidence scale.** Chains score on the same 1–10 scale and the same six-question rubric as everything else (see [False Positive Filtering](./false-positive-filtering.md)). There is no separate chain scale.
4. **Tier C is input, not output noise.** A finding that is not a vulnerability on its own (an info leak of internal IDs, a verbose error, a permissive default) is exactly the kind of link that makes a chain. Feed the full Phase-2 output in, Tier C included.

## Inputs

- Every Phase-2 verdict (Tier A, B, **and C**), each with its `finding_id`, `file`, `line_start`, `cwe_id`, `score`, `attack_path`, `prerequisites`, and (where the sink or source is a state the attacker gains or needs) an implicit postcondition/precondition.
- The Phase-0 inventory, for trust-boundary and role context when reasoning about what a hop crosses.

## Chain-discovery method

Adapted from the correlation model in offensive chain-analysis tooling, reframed for read-only source review:

1. **Extract each finding's precondition and postcondition.**
   - *Precondition* — what the attacker must already have for this finding to be reachable (an authenticated session, a valid token for any account, a specific role, knowledge of an ID).
   - *Postcondition* — what the attacker gains by exploiting it (a leaked internal ID, a forgeable token, read access to a record, write access to a config, code execution).
   These come straight from the finding's `prerequisites` (precondition) and `attack_path` / impact (postcondition).

2. **Identify entry links.** A finding is a valid chain *entry* if its precondition is satisfiable by an external or cross-tenant principal with no prior compromise — i.e. its own reachability (rubric Q1) and attacker-control (Q2) are already established. Tier A/B findings with confirmed reachability are the usual entries; a Tier C finding is an entry only if it too is externally reachable.

3. **Find hops.** Finding B can follow finding A when **A's postcondition satisfies B's precondition** — the token A forges is the token B's endpoint accepts; the ID A leaks is the ID B's IDOR needs. Match on the concrete capability, not on category.

4. **Trace to an objective.** Walk hops until reaching a terminal finding whose postcondition is a real objective: cross-tenant data access, RCE, auth bypass, privilege escalation, secret disclosure. A chain with no high-impact terminal is not worth reporting as a chain — its components already stand on their own.

5. **Prefer the shortest viable chain.** When several paths reach the same objective, keep the one with the fewest hops and the most-verified transitions. Note alternatives in one line; don't enumerate every permutation.

## Scoring a chain

Apply the six-question rubric to the chain **as a unit**:

- **Reachability (Q1) and attacker-control (Q2)** are taken from the **entry link**. If the entry isn't reachable by an unprivileged attacker, the chain isn't either.
- **Impact (Q4)** is taken from the **terminal link** — this is why a chain can outscore every one of its components. Each component was capped on its *own* impact (an info leak maxes at 5); the chain inherits the objective's impact instead.
- **Prerequisites (Q5)** is the union of every hop's residual prerequisites that the chain does not itself satisfy. A chain that still needs three independent external conditions is capped at 6, same as any finding.
- **Evidence (Q6)** governs the **hop transitions.** Every hop must cite the specific finding postcondition and precondition it connects. The chain's score is capped by its **least-evidenced transition**: if any hop is asserted without a concrete postcondition→precondition match, the chain drops one tier (and if that hop is outright speculative, cap at Tier B and mark the chain speculative per constraint 1).

The result tiers exactly like any finding: ≥7 Tier A, 4–6 Tier B, ≤3 Tier C.

## Highest-leverage remediation

After scoring, compute the **single fix that breaks the most chains.** For each component finding, count the distinct Tier-A/B chains it appears in; the finding with the highest count is the highest-leverage remediation, even if its own standalone score is low. Surface this explicitly in Phase 3 — it is often the most actionable line in the whole report, because fixing one Tier-C info leak can sever three Tier-A chains at once.

## MITRE ATT&CK mapping

Tag each hop with the ATT&CK technique that best describes the attacker *behavior* at that step (e.g. `T1528` steal application access token, `T1548` abuse elevation control, `T1530` data from cloud storage). CWE/ASVS describe the *code defect*; ATT&CK describes the *action*, which is the right vocabulary for a multi-step path. Record them in the chain's `attack_techniques` array. Mapping is best-effort — if no technique fits a hop, write `none` for that hop rather than forcing one.

## Output

Chain synthesis emits zero or more `chain` findings matching the chain variant in [Finding Schema](./finding-schema.md). Each carries its ordered `component_finding_ids`, per-hop transitions with ATT&CK tags, an entry/terminal designation, and a chain-level score. Phase 3 renders Tier-A/B chains in a dedicated section — see [Output Format](./output-format.md).

If no component findings compose into a high-impact chain, say so in one line. A pipeline that finds no chains is the common, healthy case — do not manufacture one to fill the section.
