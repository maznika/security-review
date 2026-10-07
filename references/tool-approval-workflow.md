# Tool Approval Workflow

Use this workflow before installing or executing any tool not explicitly approved in [approved-tool-catalog.md](./approved-tool-catalog.md).

## When approval is required
- The tool is not listed in the approved catalog.
- The tool is listed, but requested usage is outside approved modes.
- A reusable script is newly created for security review operations.

## Request contents
Provide the following in a PR or approval request:
1. Tool name and version.
2. Purpose and expected security value.
3. Execution model (static, dynamic, networked, local-only).
4. Data access scope (files, network, credentials, artifacts).
5. Risk assessment and mitigations.
6. Rollback/removal plan.
7. Example invocation and expected output.

## Review criteria
Approvers should evaluate:
1. Security benefit and signal quality.
2. Operational risk and blast radius.
3. Data handling and privacy impact.
4. Reproducibility and maintenance burden.
5. Fit with existing approved tools.

## Decision outcomes
- Approved: Add to catalog with constraints and examples.
- Approved with conditions: Add explicit limits and expiration/review date.
- Rejected: Document rationale and alternatives.

## Post-approval requirements
1. Update [approved-tool-catalog.md](./approved-tool-catalog.md).
2. Update [tool-safety-rules.md](./tool-safety-rules.md) if new constraints are needed.
3. Reference the approval artifact (PR/issue) from the catalog entry.
