# references/

Loaded on demand from [SKILL.md](../SKILL.md), keeping the initial skill load small.

## Pipeline

| Doc | Phase | Purpose |
|---|---|---|
| [analysis-methodology.md](./analysis-methodology.md) | all | The five-phase pipeline in detail |
| [inventory-pass.md](./inventory-pass.md) | 0a | Classifier commands and inventory JSON schema |
| [discovery-lanes.md](./discovery-lanes.md) | 1 | The 14 lanes, scope predicates, ASVS/CWE checklists |
| [asvs-v5-chapters.md](./asvs-v5-chapters.md) | 1, 3 | ASVS v5.0.0 chapter list, lane→chapter mapping, citation format — the source of truth for every ASVS label |
| [false-positive-filtering.md](./false-positive-filtering.md) | 1, 2 | Hard exclusions, precedents, six-question scoring rubric |
| [chain-synthesis.md](./chain-synthesis.md) | 2.5 | Composing verified findings into scored attack chains |
| [finding-schema.md](./finding-schema.md) | 1, 2, 2.5, 3 | JSON contract for inter-agent handoff, incl. the chain variant |
| [output-format.md](./output-format.md) | 3 | Tier A/B/C report structure, chains, coverage report |

## Governance

| Doc | Purpose |
|---|---|
| [approved-tool-catalog.md](./approved-tool-catalog.md) | Canonical list of approved tools and execution modes |
| [tool-safety-rules.md](./tool-safety-rules.md) | Non-negotiable constraints and prohibited patterns |
| [tool-approval-workflow.md](./tool-approval-workflow.md) | Process for adding a tool to the catalog |

## Invariants

- **The confidence threshold lives in [SKILL.md](../SKILL.md).** Every doc here defers to that table. If you change the cutoff, change it there and update the rubric in `false-positive-filtering.md` to match.
- **Every tool named in any doc must have a catalog entry.** A tool referenced but uncatalogued is a defect.
