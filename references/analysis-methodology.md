# Analysis Methodology

Five sequential phases (0, 1, 2, 2.5, 3). Each phase consumes the previous phase's artifact and produces a structured artifact for the next.

## Phase 0 — Inventory and seed findings

### Phase 0a — Inventory

Goal: produce a deterministic file inventory so every run of the same PR starts from the same attack surface.

Output: a single JSON file written to `.security-review/inventory.json` at the repo root (excluded locally through `.git/info/exclude`, so it is never committed).

See [Inventory Pass](./inventory-pass.md) for the exact commands and JSON schema.

### Phase 0b — Automated static analysis (seed findings)

Goal: give the lanes a head start on where to look. Run the approved static-analysis tools against the in-scope files from 0a and collect a structured candidate list.

This is the **only phase in this skill where shell execution is permitted**, and only for tools listed in [Approved Tool Catalog](./approved-tool-catalog.md). Everything from Phase 1 onward is read-only.

#### Tooling options (use whichever are available in the environment)

| Tool | Command | Focus |
|---|---|---|
| **Bandit** | `bandit -r . -ll -f json` | Python SAST: injection, crypto, shell, hardcoded creds |
| **Ruff** | `ruff check --select S,B,E .` | Python: security (S/flake8-bandit) + bugbear (B) rules |
| **Semgrep** | `semgrep scan --metrics=off --config=p/secrets --config=p/<lang> .` (one `p/<lang>` per inventory language, e.g. `p/python`, `p/typescript`) | Multi-pattern SAST + secrets |
| **TruffleHog** | `trufflehog git "file://$PWD" --no-verification --no-update --json`, filtered to location and type ([catalog](./approved-tool-catalog.md#secret-scanning-trufflehog)) | Secret scanning, incl. git history |

Scope each tool to the inventory's file list where the tool supports it. If none of these are available, record that in the Phase 3 coverage report and proceed — Phase 0b is an accelerant, not a gate.

#### How to use the output

- Collect all tool findings into a structured list with rule ID, file, line, and message.
- Treat each as an **unvalidated candidate** — a seed, not a finding. Seeds still pass through Phase 2 filtering like any other candidate.
- Route each seed to the lane whose scope predicate matches its file, and pass it as extra context in that lane's prompt.
- **Lanes must work their full checklist independently of the seeds.** Tools miss context-dependent vulnerabilities — logic flaws, auth bypass, IDOR, tenant-isolation breaks — entirely. A clean tool run is not coverage.
- Treat the *absence* of tool findings in an area as a reason to look harder there, not as evidence of safety.
- Investigate the surrounding context of each seed, not just the flagged line.

## Phase 1 — Parallel discovery

Goal: enumerate candidate findings with uniform coverage across lanes.

Rules:

1. **Read the inventory first.** Each lane's _scope predicate_ is evaluated against the inventory, with content clauses checked by read-only search. Give every lane a [coverage status](#coverage-statuses); never skip a lane silently.
2. **Fan out in a single message.** Multiple `Agent` tool uses in one assistant message run concurrently. Sequential calls across messages defeat the purpose. If the runtime has no parallel-subagent primitive, run the lanes sequentially in one context instead — coverage is the requirement, concurrency is the optimization.
3. **One Agent per lane.** Do not let a single Agent cover multiple lanes — coverage attribution breaks and prompts get too broad.
4. **Read-only.** Use `subagent_type: Explore` for every lane. No writes and no execution; search per [Tool Safety Rules — Subagent constraints](./tool-safety-rules.md#subagent-constraints).
5. **Structured output.** Each lane returns a JSON array of findings matching [Finding Schema](./finding-schema.md). Free-form prose is rejected.
6. **Apply filtering rules during discovery.** Each lane prompt must reference [False Positive Filtering](./false-positive-filtering.md) so obvious noise never enters the candidate list.
7. **Pass seeds, don't defer to them.** Include the Phase-0b seeds whose files match the lane's predicate as extra context. The lane still works its full checklist; seeds neither bound nor satisfy it.

For the lane catalog, scope predicates, and per-lane checklists, see [Discovery Lanes](./discovery-lanes.md).

### Coverage statuses

Every lane gets exactly one status in the Phase 3 coverage report:

| Status | Meaning |
|---|---|
| `ran` | The predicate matched; the lane ran on those files. |
| `ran (predicate gap)` | The repository plainly has the lane's surface (a browser UI, an OAuth flow, request handlers) but the predicate matched nothing. Run the lane on the files that carry the surface and list them in the notes. |
| `n/a` | The surface exists, but a precedent rules the lane out (e.g. L03 on client-only code: the server is authoritative). |
| `skipped` | The surface is absent (e.g. no C/C++ files for L09). |
| `failed` | The lane errored or returned output that failed validation. |

A predicate gap means the role rules missed a layout. Note it in the run artifact so the rules can be extended.

## Phase 2 — Parallel false-positive filtering

Goal: assign a confidence score (1–10) to each candidate and produce a verified attack path.

Rules:

1. **One Agent per candidate.** Fan out in a single message.
2. **Read-only Explore agent.** Same constraint as Phase 1.
3. **Single rubric.** Use the scoring rubric in [False Positive Filtering](./false-positive-filtering.md) — do not invent ad-hoc criteria.
4. **Structured output.** Each filter agent returns a JSON object with `score`, `rationale`, `attack_path`, `prerequisites`, and `evidence_lines` matching [Finding Schema](./finding-schema.md).
5. **Independence.** Filter agents must not see other candidates' verdicts — this prevents anchoring bias and keeps verdicts comparable across runs.

## Phase 2.5 — Chain synthesis

Goal: compose independently-verified findings into multi-step attack paths whose impact exceeds any single component.

The independence that Phases 1–2 enforce is what makes this phase necessary — no earlier agent can see across findings, so no earlier agent can spot a chain. This is the first and only step with global visibility.

Steps (executed in the main thread, no agents):

1. **Gather all Phase-2 verdicts**, including Tier C — a non-vulnerability can still be a link.
2. **Extract each finding's precondition and postcondition** from its `prerequisites` and `attack_path`.
3. **Match postcondition → precondition** to find hops; trace from an externally-reachable entry link to a high-impact terminal link. Prefer the shortest viable chain.
4. **Score each chain** on the same six-question rubric: reachability from the entry, impact from the terminal, capped by the least-evidenced hop transition. Compose only existing findings — a chain needing an unfound hop is speculative and capped at Tier B.
5. **Compute the highest-leverage fix** — the component finding appearing in the most Tier-A/B chains.
6. **Emit `chain` findings** matching the chain variant in [Finding Schema](./finding-schema.md).

Skip this phase if fewer than two findings survived Phase 2. See [Chain Synthesis](./chain-synthesis.md) for the discovery method, scoring detail, and hard constraints.

## Phase 3 — Synthesis

Goal: produce a deterministic, tiered report with explicit coverage reporting.

Steps (executed in the main thread, no agents):

1. **Dedupe** findings by `(file, line_start, cwe_id)`. Keep the highest-confidence verdict for each tuple.
2. **Tier** each finding by confidence score (this is confidence, not severity):
   - `score >= 7` → **Tier A** (main report)
   - `4 <= score <= 6` → **Tier B** (needs-human-review appendix)
   - `score <= 3` → **Tier C** (run artifact only, not rendered)
3. **Render** per [Output Format](./output-format.md).
4. **Coverage report.** Append a table listing every lane with its [coverage status](#coverage-statuses) and the reason. Account for every ASVS chapter across **V1–V17** as touched, not touched, or not applicable, deriving all three lists from the lane mapping in [asvs-v5-chapters.md](./asvs-v5-chapters.md) — a chapter in none of them means the mapping and the report have diverged. Record which Phase-0b tools ran and which were unavailable — an absent scanner is a coverage caveat the reader needs. This is the auditable record that justifies "we looked everywhere we should have."
5. **Run artifact.** Save the full Phase-1 candidate list and Phase-2 verdicts (including Tier C) to `.security-review/<timestamp>/run.json`. This allows run-to-run diffing.
