# Phase 0 — Inventory Pass

Produces a deterministic JSON inventory of files in scope. Every later phase reads this artifact, so two runs of the same PR start from the same attack surface.

## Commands

Run from the repo root. If no scope argument was given, default to the pending changes on the current branch.

```bash
# 1. Establish the output directory. It is excluded locally through .git/info/exclude,
#    so no tracked file (such as .gitignore) changes.
OUT=.security-review
mkdir -p "$OUT"
EXCLUDE="$(git rev-parse --git-path info/exclude)"
grep -qxF "/$OUT/" "$EXCLUDE" 2>/dev/null || echo "/$OUT/" >> "$EXCLUDE"

# 2. Identify in-scope files, one path per line, deletions excluded.
#    Branch / PR mode (default): diff against the remote's default branch.
BASE="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || echo origin/main)"
git diff --name-only --diff-filter=d "$BASE...HEAD" > "$OUT/.changed-files"

#    Directory / file scope (when invoked with an explicit path):
#    find <path> -type f -not -path '*/.git/*' > "$OUT/.changed-files"

# 3. Run the classifier (inlined here so the skill is self-contained; standard library only)
OUT="$OUT" python3 - <<'PY' > "$OUT/inventory.json"
import json, os, re
from pathlib import Path

LANGUAGE_BY_EXT = {
    ".go": "go", ".py": "python", ".ts": "typescript", ".tsx": "typescript",
    ".mts": "typescript", ".cts": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".php": "php", ".rs": "rust",
    ".cs": "csharp", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".c": "c", ".h": "c",
    ".proto": "proto", ".tf": "terraform", ".jsonnet": "jsonnet", ".libsonnet": "jsonnet",
    ".yaml": "yaml", ".yml": "yaml", ".sql": "sql", ".sh": "shell",
    ".md": "markdown",
}

MCP = r"(?i:(^|[/_.-])mcp([/_.-]|$))"

ROLE_RULES = [
    # Build, CI, and infrastructure: identified by file name or directory.
    (re.compile(r"(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|go\.mod|Cargo\.toml"
                r"|Gemfile|pom\.xml|build\.gradle(\.kts)?|composer\.json|aqua\.yaml)$"),
                                                            "dependency_manifest"),
    (re.compile(r"(^|/)\.github/workflows/"),               "gha_workflow"),
    (re.compile(r"(^|/)(BUILD|BUILD\.bazel|WORKSPACE|WORKSPACE\.bazel|MODULE\.bazel)$"),
                                                            "bazel_build"),
    (re.compile(r"(^|/)(kube|k8s|kubernetes|helm|charts)/"),
                                                            "kube_manifest"),
    (re.compile(r"(^|/)terraform/|/iam/|\.tfvars?$|\.tf$"), "terraform"),
    (re.compile(r"\.(jsonnet|libsonnet)$"),                 "jsonnet"),
    (re.compile(r"\.proto$"),                               "proto_schema"),
    # MCP servers and tools, in any language.
    (re.compile(MCP),                                       "mcp_tool"),
    # Python web conventions (Django / DRF / Celery layout).
    (re.compile(r"(^|/)migrations/.*\.py$"),                "django_migration"),
    (re.compile(r"(^|/)views?(/.*)?\.py$"),                 "django_view"),
    (re.compile(r"(^|/)serializers?(/.*)?\.py$"),           "drf_serializer"),
    (re.compile(r"(^|/)models?(/.*)?\.py$"),                "django_model"),
    (re.compile(r"(^|/)tasks?(/.*)?\.py$"),                 "celery_task"),
    (re.compile(r"(^|/)middlewares?(/.*)?\.py$"),           "django_middleware"),
    (re.compile(r"(^|/)settings(/.*|_[^/]*)?\.py$"),        "django_settings"),
    # Web frontends and server request handlers in any language.
    (re.compile(r"\.(tsx|jsx|vue|svelte)$"),                "frontend_component"),
    (re.compile(r"(^|/)(routes?|controllers?|handlers?|endpoints?)/"),
                                                            "http_handler"),
]

TRUST_BOUNDARY_RULES = [
    (re.compile(r"(^|/)views?(/|\.py$)|(^|/)(api|handlers?|routes?|controllers?|endpoints?)/|" + MCP),
                                                            "external_http"),
    (re.compile(r"warehouse|(^|/)(connectors?|webhooks?)/"), "external_connector"),
    (re.compile(r"(^|/)((auth|authn|authz)[/._-]|login|logout|oauth|oidc|saml|sso|pkce|session)"),
                                                            "authn_boundary"),
    (re.compile(r"/iam/|\.tf$|(^|/)(kube|k8s|kubernetes|helm|charts)/"),
                                                            "infrastructure_privilege"),
    (re.compile(r"(^|/)tasks?(/.*)?\.py$|celery|temporal|(^|/)(jobs?|workers?)/"),
                                                            "background_job"),
]

TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]*\.py$|_test\.[a-z]+$"
    r"|\.(test|spec)\.[cm]?[jt]sx?$|Tests?\.(java|kt|cs)$"
)

def classify(path: str) -> dict:
    ext = Path(path).suffix
    lang = LANGUAGE_BY_EXT.get(ext, "other")
    role = next((r for pat, r in ROLE_RULES if pat.search(path)), "unknown")
    boundary = next((b for pat, b in TRUST_BOUNDARY_RULES if pat.search(path)), None)
    return {
        "path": path, "language": lang, "role": role,
        "trust_boundary": boundary,
        "is_test": bool(TEST_PATH.search(path)),
    }

out = Path(os.environ.get("OUT", ".security-review"))
paths = [line for line in (out / ".changed-files").read_text().splitlines() if line]

files = [classify(p) for p in sorted(set(paths))]

deps_changed = [f["path"] for f in files if f["role"] == "dependency_manifest"]

print(json.dumps({
    "scope": os.environ.get("REVIEW_SCOPE", "branch_vs_default"),
    "file_count": len(files),
    "files": files,
    "deps_changed": deps_changed,
    "roles_present": sorted({f["role"] for f in files}),
    "languages_present": sorted({f["language"] for f in files}),
    "trust_boundaries_present": sorted({f["trust_boundary"] for f in files if f["trust_boundary"]}),
}, indent=2))
PY

# 4. Print a one-line summary to the user
jq -r '"Inventory: \(.file_count) files | roles: \(.roles_present | join(",")) | boundaries: \(.trust_boundaries_present | join(","))"' \
   "$OUT/inventory.json"
```

If `origin/HEAD` is not set (some clones skip it), `git remote set-head origin --auto` sets it; otherwise pass the base branch explicitly.

## Inventory JSON schema

```json
{
  "scope": "branch_vs_default | explicit_path | full_repo",
  "file_count": 42,
  "files": [
    {
      "path": "app/invoices/views.py",
      "language": "python",
      "role": "django_view",
      "trust_boundary": "external_http",
      "is_test": false
    }
  ],
  "deps_changed": ["package.json"],
  "roles_present": ["django_view", "frontend_component"],
  "languages_present": ["python", "typescript"],
  "trust_boundaries_present": ["external_http"]
}
```

## How lanes consume the inventory

Each lane in [Discovery Lanes](./discovery-lanes.md) declares a _scope predicate_ over this JSON (e.g. "role in {django_view, drf_serializer}" or "language == cpp and not is_test"), often with a content clause evaluated by read-only search. If the predicate matches zero files, the lane is **skipped** and recorded as such in the Phase 3 coverage report — not silently omitted. If the repository plainly has the lane's surface anyway, record a predicate gap instead ([Coverage statuses](./analysis-methodology.md#coverage-statuses)).

The role and trust-boundary rules are generic path conventions that apply to any repository. The Python web rules follow Django / DRF / Celery naming, so a `views.py` in another framework is still classified `django_view`; L07's checklist simply finds nothing Django-specific there. To tune for a specific monorepo layout, add a block of path rules at the top of `ROLE_RULES` (first match wins) rather than editing the generic rules.

## Determinism notes

- `sorted(set(paths))` ensures stable ordering regardless of git diff output order.
- Role classification is deterministic (first matching regex wins, rules ordered most-specific-first).
- The script is self-contained and pinned in this doc — do not refactor it into an external file without updating this reference.
