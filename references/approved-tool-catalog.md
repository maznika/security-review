# Approved Tool Catalog

This document is the canonical source of approved tools and allowed execution modes for this skill.

Any tool named anywhere in the skill must have an entry here. If a phase references a tool this catalog does not list, that is a defect in the skill — fix it here before running.

## Status values
- Approved: Allowed for use under listed constraints.
- Conditional: Allowed only when specified conditions are met.
- Not Approved: Must not be used in this workflow.

## Output handling policy
- Temp-file output is allowed for large result sets.
- Summarize relevant findings back into the review output.
- Do not store secrets, credentials, or production data in temp files.

## Approved tools

### Python static analysis (Bandit)
- Status: Approved
- Purpose: Static analysis for Python security issues.
- Allowed modes:
  - Local static analysis against repository code.
  - Read-only result interpretation.
- Constraints:
  - Do not run against production systems.
  - Findings must still pass false-positive filtering rules.
- Reference: https://github.com/pycqa/bandit

### Python lint + security rules (Ruff)
- Status: Approved
- Purpose: Fast Python security (`S`/flake8-bandit) and bugbear (`B`) rule coverage.
- Allowed modes:
  - Local static analysis against repository code: `ruff check --select S,B,E .`
  - Read-only result interpretation.
- Constraints:
  - Do not run `--fix`; this skill never modifies code.
  - Findings are Phase 0b seeds and must still pass false-positive filtering.
- Reference: https://github.com/astral-sh/ruff

### Multi-language SAST + secrets (Semgrep)
- Status: Approved
- Purpose: Multi-pattern static analysis and secret detection across languages.
- Allowed modes:
  - Local analysis with registry rulesets: `semgrep scan --metrics=off --config=p/secrets --config=p/<lang> .`, with one `p/<lang>` per language in the inventory (e.g. `p/python`, `p/javascript`, `p/typescript`, `p/golang`).
  - Read-only result interpretation.
- Constraints:
  - Always pass `--metrics=off`. Downloading registry rulesets is fine; uploading source, findings, or usage metrics is not.
  - Run in local/offline mode where available; do not upload findings or source to a Semgrep account from a review run.
  - Do not use `--autofix`.
  - Findings are Phase 0b seeds and must still pass false-positive filtering.
- Reference: https://github.com/semgrep/semgrep

### Secret scanning (TruffleHog)
- Status: Conditional
- Purpose: Detect committed secrets and credentials, including in git history.
- Allowed modes (run from the repository root):
  - Git history: `trufflehog git "file://$PWD" --no-verification --no-update --json`
  - Working tree: `trufflehog filesystem . --no-verification --no-update --json`
- Constraints:
  - Use a `trufflehog` binary that is already installed (for example through Homebrew or IT-managed tooling) or a wrapper vendored in the target repository. Never install it during a review.
  - Always pass `--no-verification`: verification sends candidate secrets to third-party APIs. Always pass `--no-update`, so the scanner makes no network calls of its own.
  - **Secret values must never reach review output, logs, or temp files** — report location and type only. Filter the JSON before anything is written, for example: `| jq -c '{detector: .DetectorName, file: (.SourceMetadata.Data.Git.file // .SourceMetadata.Data.Filesystem.file), line: (.SourceMetadata.Data.Git.line // .SourceMetadata.Data.Filesystem.line), commit: .SourceMetadata.Data.Git.commit}'`
  - Results are unverified candidates: Phase 0b seeds that still pass false-positive filtering.
- Reference: https://github.com/trufflesecurity/trufflehog

### GitHub code scanning
- Status: Conditional
- Purpose: Reuse existing code scanning results where available.
- Allowed modes:
  - Read existing alerts and metadata.
  - Correlate alerts with code context.
- Constraints:
  - Do not auto-close or auto-modify alerts.
  - Treat as input signal, not final verdict.
- Reference: https://docs.github.com/en/code-security/secure-coding/automated-code-scanning/about-code-scanning

## Adding a new tool
Follow the process in [tool-approval-workflow.md](./tool-approval-workflow.md) before installation or execution.
