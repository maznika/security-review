# Tool Safety Rules and Prohibited Patterns

These rules apply to all tooling used by this security review skill.

## Mandatory safety rules
1. Use approved tools only, and only in approved execution modes.
2. Run active testing only against staging endpoints that do not contain sensitive data.
3. Prefer read-only analysis whenever possible.
4. Keep artifacts and outputs inside approved project boundaries.
5. Shell commands are permitted **in Phase 0 only** (inventory and SAST seeding), and only for tools and modes listed in the approved catalog. Phases 1–3 are read-only: no execution, only the read-only search and inspection allowed under [Subagent constraints](#subagent-constraints).
6. Temporary files are permitted for intermediate analysis output in system temp locations, but must not contain secrets, credentials, or production data. Secret-scanner hits are recorded as location and type only — never the secret value.

## Prohibited patterns
1. Never pipe output from a web request directly into a shell.
2. Never execute remote scripts fetched at runtime without prior review and approval.
3. Never install or execute unapproved tools during a formal review.
4. Never run active security testing against production endpoints.
5. Never exfiltrate code, credentials, or security artifacts to unapproved external systems.
6. Never bypass repository or organization security controls.

## Subagent constraints
For Phase 1 discovery-lane agents and Phase 2 false-positive filtering agents alike:
- Read code only. Launch with `subagent_type: Explore`.
- Search with the runtime's read-only tools (Read, Grep, Glob). If the runtime has no search tools, read-only shell inspection is allowed: `grep`/`rg`, `find`, `ls`, `cat`, `head`, `tail`, `sed -n`, `wc`, and `git log`/`show`/`grep`/`blame`.
- Never execute anything else: no builds, tests, package managers, installers, interpreters on repository files, network tools, or redirections that write files.
- Do not modify repository files.
- Stay within the assigned lane predicate or candidate.

## Escalation
If a required action conflicts with these rules, stop and request approval through [tool-approval-workflow.md](./tool-approval-workflow.md).
