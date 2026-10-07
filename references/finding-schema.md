# Finding Schema

All inter-agent handoffs use this schema. Lane agents (Phase 1) emit _candidate_ findings without `score`, `attack_path`, etc. Filter agents (Phase 2) emit _verified_ findings with all fields populated. Phase 2.5 emits a distinct **chain** variant (see [Chain finding variant](#chain-finding-variant) below) that composes verified findings.

## JSON schema

```json
{
  "finding_id": "L03-007",
  "lane": "L03",
  "file": "app/invoices/views.py",
  "line_start": 142,
  "line_end": 148,
  "asvs_id": "V8.1.2",
  "cwe_id": "CWE-639",
  "attack_technique": "T1530",
  "category": "tenant_isolation",
  "severity": "high",
  "title": "Invoice fetch by ID does not check account ownership",
  "description": "View resolves Invoice.objects.get(id=request.GET['id']) without filtering by request.user.account_id, allowing IDOR across accounts.",
  "evidence_snippet": "invoice = Invoice.objects.get(id=request.GET['id'])",
  "evidence_lines": [142, 145, 148],

  "score": 9,
  "rationale": "Reachable from any authenticated user; no account scope on the queryset; impact is cross-tenant read of invoice contents.",
  "attack_path": "Authenticated user A enumerates invoice IDs and requests /api/invoices/?id=<invoice_owned_by_B>, receiving B's invoice JSON.",
  "prerequisites": [
    "any authenticated session",
    "knowledge of a target invoice id (4-byte int, enumerable)"
  ],

  "recommendation": "Use Invoice.objects.filter(id=..., account_id=request.user.account_id).first() and 404 on miss. Add a regression test asserting cross-account access returns 404."
}
```

## Field definitions

| Field                    | Required when | Notes                                                                                                        |
| ------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------ |
| `finding_id`             | always        | Format `L<lane>-<seq>`. Stable within a run; do not reuse across runs.                                       |
| `lane`                   | always        | One of `L01`..`L14`.                                                                                         |
| `surface`                | always        | `application_code` \| `infrastructure` \| `ci_dependencies` \| `design`. Derived from the lane — see the [lane index](./discovery-lanes.md#lane-index). Routes the fix to the right owner; the report groups by it within a tier. |
| `file`                   | always        | Repo-relative path matching an entry in the inventory.                                                       |
| `line_start`, `line_end` | always        | Use `0, 0` only for `category: design_concern` from L14.                                                     |
| `asvs_id`                | always        | ASVS v5.0 requirement ID (e.g. `V8.1.2`); chapters, sections, and the citation format are in [asvs-v5-chapters.md](./asvs-v5-chapters.md). Verify a specific requirement exists before citing it. Use `N/A` only for L09 (C/C++ memory safety) and L14 (design). |
| `cwe_id`                 | always        | Single best-fit CWE ID.                                                                                      |
| `attack_technique`       | optional      | Best-fit MITRE ATT&CK technique ID for the attacker _behavior_ (e.g. `T1530`). `none` if no technique fits. CWE names the defect; ATT&CK names the action. Always set for chain hops (see below). |
| `category`               | always        | Short snake_case label (e.g. `sql_injection`, `tenant_isolation`, `audit_log_policy_gap`, `design_concern`). |
| `severity`               | always        | `critical` \| `high` \| `medium` \| `low` \| `info` per [Output Format](./output-format.md#severity-guidelines). Lowercase in the JSON; rendered in Title case in the report. |
| `title`                  | always        | One-line summary, ≤100 chars.                                                                                |
| `description`            | always        | 2–4 sentences. WHY this is a vulnerability.                                                                  |
| `evidence_snippet`       | always        | The literal line(s) of code that demonstrate the issue.                                                      |
| `evidence_lines`         | always        | Array of line numbers cited as evidence.                                                                     |
| `score`                  | Phase 2 only  | Integer 1–10 per the rubric in filtering doc.                                                                |
| `rationale`              | Phase 2 only  | 1–3 sentence justification for the score.                                                                    |
| `attack_path`            | Phase 2 only  | Step-by-step exploitation, even for low/medium.                                                              |
| `prerequisites`          | Phase 2 only  | Array of conditions that must hold.                                                                          |
| `recommendation`         | Phase 2 only  | Concrete fix, preferably referencing an in-repo precedent or library.                                        |

## Why every field is required

- `asvs_id` + `cwe_id` make coverage measurable across runs and let the report be diffed against an external taxonomy.
- `evidence_lines` enables mechanical verification — Phase 3 can `git diff` to confirm the lines exist.
- `attack_path` + `prerequisites` are what a human reviewer needs to triage in under a minute.
- `recommendation` keeps the finding actionable. Reports without it get ignored.

## Chain finding variant

Phase 2.5 ([Chain Synthesis](./chain-synthesis.md)) emits `chain` findings that compose two or more verified findings into a multi-step attack path. A chain reuses the common fields (`finding_id`, `severity`, `score`, `rationale`, `recommendation`) and replaces the single-location fields with path fields.

```json
{
  "finding_id": "CH-001",
  "kind": "chain",
  "title": "Cross-tenant invoice read via token audience confusion",
  "severity": "high",
  "score": 8,
  "component_finding_ids": ["L02-003", "L03-007"],
  "entry_finding_id": "L02-003",
  "terminal_finding_id": "L03-007",
  "hops": [
    {
      "from": "L02-003",
      "to": "L03-007",
      "postcondition": "attacker mints a JWT the invoice service accepts (no aud check)",
      "precondition": "invoice IDOR requires any token valid for the service",
      "evidence": "L02-003 proves the missing aud check; L03-007 proves the queryset is unscoped by account_id",
      "attack_technique": "T1528"
    }
  ],
  "attack_techniques": ["T1528", "T1530"],
  "objective": "Read any tenant's invoice contents",
  "residual_prerequisites": ["an authenticated session in any account"],
  "speculative": false,
  "rationale": "Entry (L02-003) is reachable by any authenticated user; terminal impact is cross-tenant read. Both hop endpoints are evidence-backed, so no tier drop.",
  "recommendation": "Fixing either link breaks the chain; L02-003 (add aud validation) is the higher-leverage fix — it also severs chain CH3."
}
```

### Chain field definitions

| Field                    | Required when | Notes                                                                                                          |
| ------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------- |
| `kind`                   | chain only    | Literal `"chain"`. Distinguishes from single-location findings (which omit `kind` or set `"finding"`).         |
| `component_finding_ids`  | chain only    | Ordered array of the `finding_id`s composed, entry → terminal. Every ID must exist in the Phase-2 output.       |
| `entry_finding_id`       | chain only    | The reachable-by-an-unprivileged-attacker link. Its Q1/Q2 set the chain's reachability.                        |
| `terminal_finding_id`    | chain only    | The objective link. Its impact sets the chain's Q4.                                                            |
| `hops`                   | chain only    | Array of `{from, to, postcondition, precondition, evidence, attack_technique}`. One per transition.            |
| `attack_techniques`      | chain only    | De-duplicated array of every hop's ATT&CK technique.                                                           |
| `objective`              | chain only    | One-line statement of what full success yields.                                                               |
| `residual_prerequisites` | chain only    | Prerequisites the chain does _not_ satisfy itself (feeds rubric Q5).                                           |
| `speculative`            | chain only    | `true` if any hop lacks a concrete postcondition→precondition match. Speculative chains are capped at Tier B.  |

A chain **must not** introduce a vulnerability absent from `component_finding_ids`. Phase 3 rejects any chain citing a `finding_id` not present in the Phase-2 verdicts, the same way it rejects a finding with a missing required field.

## Validation

In Phase 3 (main thread), reject any finding missing a required field. Log rejections to the run artifact under `validation_errors`. Do not silently drop — the lane agent should be re-prompted with the specific missing field. For chains, additionally reject any `component_finding_ids` entry that does not resolve to a real Phase-2 finding.
