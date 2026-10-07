# Discovery Lanes

14 lanes. Each lane has a **scope predicate** over the Phase-0 inventory and a **checklist** mapped to OWASP ASVS v5.0 chapters and common CWE IDs. A lane only runs if its predicate matches at least one file.

**Predicates.** Role, path, and trust-boundary clauses are evaluated against the inventory. Content clauses (`content matches …`, case-insensitive extended regex) are evaluated with a read-only search over the inventory's non-test files. The role rules are generic path conventions, and the content clauses cover layouts they don't recognize. If a repository plainly has a lane's surface but the predicate still matches nothing, that is a predicate gap, not a skip — see [Coverage statuses](./analysis-methodology.md#coverage-statuses).

**ASVS chapters.** Numbers, titles, and the lane→chapter mapping live in [asvs-v5-chapters.md](./asvs-v5-chapters.md) — the single source of truth. Cite requirement IDs as `V<chapter>.<section>.<requirement>` (e.g. `V10.2.3`); when the exact requirement is unclear, cite the section (`V10.2`). Do not relabel a chapter here without updating that file.

Every lane Agent receives:

1. The full inventory JSON (read-only).
2. The lane's scope predicate (so it only opens matching files).
3. The lane's checklist (its sole rubric — do not invent extra checks).
4. The [Finding Schema](./finding-schema.md) (its output contract).
5. The hard exclusions and precedents from [False Positive Filtering](./false-positive-filtering.md).

The Agent must return a JSON array of findings (possibly empty) matching the schema. No prose, no commentary.

## Lane index

Canonical short names. **Reports must show the lane name alongside the ID** — `L02 — Authentication`, not
`L02`, which tells a reader nothing. The `Surface` column routes a finding to whoever fixes it and is
carried through to the report; see [output-format.md](./output-format.md).

| Lane | Short name | Surface |
|---|---|---|
| L01 | Injection | Application code |
| L02 | Authentication | Application code |
| L03 | Authorization | Application code |
| L04 | Cryptography & secrets | Application code |
| L05 | Data exposure & logging | Application code |
| L06 | Deserialization & RCE | Application code |
| L07 | Webapp (Django) | Application code |
| L08 | Frontend (web) | Application code |
| L09 | C/C++ memory safety | Application code |
| L10 | IaC / IAM | Infrastructure |
| L11 | Supply chain | CI & dependencies |
| L12 | MCP tool boundary | Application code |
| L13 | External connectors | Application code |
| L14 | Secure-by-design | Design |


---

## L01 — Injection (SQL / command / template / NoSQL / XXE / path traversal)

**Scope predicate:** `language in {python, go, javascript, typescript, java, kotlin, ruby, php, csharp, rust, sql, c, cpp}` AND `not is_test`.
**ASVS:** V1 (Encoding & Sanitization), V5 (File Handling).
**Common CWEs:** CWE-89, CWE-78, CWE-94, CWE-22, CWE-611, CWE-1336.

Checklist:

- Raw SQL: Django `.extra()` / `.raw()` / `RawSQL`, Go `database/sql` with `fmt.Sprintf`, any `%s`-interpolated query.
- Command exec: `subprocess.run(..., shell=True)`, `os/exec.Command` with concatenated args, Python `os.system`.
- Template injection: Jinja2 / Go `text/template` rendering user-controlled template strings (not user-controlled data into a static template).
- Path traversal: `open(user_input)`, `filepath.Join` without `filepath.Clean` + prefix check, archive extraction (`tarfile`, `zipfile`) without member validation.
- XML/XXE: `lxml.etree.parse` without `resolve_entities=False`, `xml.etree` with external entity support.
- NoSQL: MongoDB `find({...request_data})` mass-assignment.

---

## L02 — Authentication, session, tokens

**Scope predicate:** `not is_test` AND (`trust_boundary == authn_boundary` OR (`role in {django_view, drf_serializer, mcp_tool, http_handler}` AND path matches `auth|login|oauth|saml|sso|token|session|jwt`) OR content matches `oauth|pkce|code_challenge|code_verifier|redirect_uri|grant_type|refresh_token|access_token|id_token|jwt|saml|set-cookie`).
**ASVS:** V6 (Authentication), V7 (Session Management), V9 (Self-contained Tokens), V10 (OAuth & OIDC).
**Common CWEs:** CWE-287, CWE-384, CWE-613, CWE-345, CWE-347.

Checklist:

- JWT: `algorithms=['none']`, `verify_signature=False`, missing `aud`/`iss` checks, key confusion (HS vs RS).
- Session: missing invalidation on logout / password change, session fixation (no rotation post-login).
- MFA / TOTP: replay window, missing rate-limit on verification, secret recovery flow weakness.
- OAuth: missing `state` parameter, `state` not bound to session, open redirect on callback `redirect_uri`.
- Signed cookies / Fernet / `itsdangerous`: secret rotation, expiry enforcement.
- Token scope in multi-tenant APIs and MCP servers — does a token issued for one tenant (project, workspace, org) ever authorize an action against another?

---

## L03 — Authorization & multi-tenant isolation

**Scope predicate:** `not is_test` AND (`role in {django_view, drf_serializer, celery_task, mcp_tool, http_handler}` OR `trust_boundary == background_job` OR content matches server-side route or handler definitions: `@app\.route|@(app|router|bp)\.(get|post|put|patch|delete)|\b(app|router)\.(get|post|put|patch|delete)\(|urlpatterns|@(Get|Post|Put|Patch|Delete|Request)Mapping`). Client-only code (SDKs, CLIs, browser bundles) is `n/a` for this lane: the server is authoritative (precedent 8).
**ASVS:** V8 (Authorization).
**Common CWEs:** CWE-285, CWE-639 (IDOR), CWE-863, CWE-732.

Checklist (the highest-risk lane in any multi-tenant system):

- Every object retrieval by ID checks the requesting principal owns / has access to the tenant (project, org, account) that owns the object.
- Every query / data fetch is scoped by the tenant key (`project_id`, `org_id`, `account_id`, …) — no global `.objects.get(id=…)` without scope.
- Cache keys include tenant scope (`f"invoice:{account_id}:{invoice_id}"`, not just the invoice id).
- Background jobs (Celery, Temporal, queue workers) carry tenant context end-to-end — don't re-fetch with elevated privileges.
- Foreign-key references / relations / shared assets: can a row in tenant A reference a row in tenant B?
- DRF `get_queryset` actually filters by the request principal — not relying on serializer fields for authorization.
- `@login_required` + per-object permission check (login alone is not authorization).
- Internal query services and query builders enforce the tenant boundary even when the query is constructed server-side, rather than trusting a tenant ID supplied by the caller.

---

## L04 — Cryptography, secrets, communication

**Scope predicate:** any file referencing `crypto|cipher|hash|hmac|kms|secret|password|tls|ssl|verify`.
**ASVS:** V11 (Cryptography), V12 (Secure Communication), V13 (Configuration, incl. V13.3 Secret Management), V16 (Security Logging & Error Handling).
**Common CWEs:** CWE-327, CWE-330, CWE-321, CWE-798, CWE-295, CWE-319.

Checklist:

- Hardcoded secrets, API keys, tokens, private keys (also run the GitHub secret-scanning MCP on the diff separately).
- Weak crypto: MD5/SHA1 for security purposes, DES, RC4, ECB mode, static IV, hand-rolled crypto.
- Weak RNG for security: `random.random()`, `math/rand` instead of `crypto/rand`, `Math.random()` for tokens.
- TLS verification disabled: `InsecureSkipVerify: true`, `verify=False`, `rejectUnauthorized: false`.
- Secret leak via logs / exceptions / telemetry / metric labels.
- Key rotation: hardcoded key IDs, missing key version handling.

---

## L05 — Data exposure & logging (incl. audit-log policy)

**Scope predicate:** `not is_test` AND (`role in {django_view, drf_serializer, celery_task, mcp_tool, http_handler}` OR `trust_boundary == background_job` OR content matches logging, telemetry, or error-serialization calls: `logger\.|logging\.|console\.(log|info|warn|error|debug)|captureException|Sentry|toDict\(|toJSON\(|traceback`).
**ASVS:** V16 (Security Logging & Error Handling), V14 (Data Protection).
**Common CWEs:** CWE-200, CWE-532, CWE-359.

Checklist:

- Sensitive data in logs/metrics/spans: PII (email, phone, full names alongside identifiers), raw request bodies or customer-supplied records. Secrets and credentials in logs belong to L04.
- API responses leak fields not intended for the principal's tier (admin-only fields in non-admin response).
- Debug endpoints / `?debug=1` parameters in production paths.
- Stack traces leaked to clients on error.
- **Audit-log policy gap (only where the repository defines an audit-log library or documented policy; Tier B by default, not Tier A vulnerability):** Mutations on auth, billing, IAM, data access/export, or deletions should call the repository's audit-log facility as its policy describes. Missing audit logs on such endpoints are _policy gaps_ — surface them with `severity: low` and `category: audit_log_policy_gap`. Do not flag missing audit logs for non-sensitive endpoints.

---

## L06 — Deserialization & RCE

**Scope predicate:** any file referencing `pickle|marshal|yaml.load|json.loads|gob|protobuf|Unmarshal|exec|eval|compile|importlib`.
**ASVS:** V1 (incl. V1.5 Safe Deserialization), V15 (Secure Coding & Architecture).
**Common CWEs:** CWE-502, CWE-94, CWE-95.

Checklist:

- Python: `pickle.loads`, `yaml.load` without `SafeLoader`, `eval`, `exec`, `compile` on untrusted input, `importlib.import_module(user_input)`.
- Go: `gob.Decode` on untrusted bytes, `json.Unmarshal` into `interface{}` followed by type assertions on attacker-controlled discriminator.
- **Protobuf:** wherever proto is decoded from untrusted input (Python, Go, C/C++), look for missing recursion-depth limits, oneof confusion, length-prefix attacks, and `protobuf-c` length-field handling in generated `*.pb-c.c` decoders.
- JS: `Function(user_input)`, `eval`, dynamic `require`.

---

## L07 — Webapp (Django) specific

**Scope predicate:** `role in {django_view, django_model, drf_serializer, django_middleware, django_migration, django_settings, celery_task}`.
**ASVS:** V1, V3 (V3.5 CSRF), V4, V5, V8 (V8.2.3 field-level access), V13, V15 (V15.3.3 mass assignment).
**Common CWEs:** CWE-352 (CSRF), CWE-89, CWE-915 (mass assignment), CWE-918.

Checklist:

- `@csrf_exempt` — every usage justified by an inline comment? Not used on session-cookie endpoints?
- DRF: `fields = '__all__'`, missing `read_only_fields` on sensitive attributes.
- Mass assignment: `Model.objects.create(**request.data)`, `setattr` loop over request keys.
- `ALLOWED_HOSTS`, `DEBUG`, `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` drift in settings.
- `MEDIA_ROOT` / `FileField` accepting uploads — MIME validation, served from a non-executing origin.
- Custom middleware that bypasses Django's authn/authz.
- Migrations that drop constraints, weaken indexes used for security, or remove FK cascades that protected isolation.

---

## L08 — Frontend (web)

**Scope predicate:** `not is_test` AND (`role == frontend_component` OR content matches browser DOM, navigation, or messaging APIs: `innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|postMessage|addEventListener\(["']message|window\.open|location\.(href|assign|replace)|localStorage|sessionStorage|DOMParser|createContextualFragment|srcdoc`).
**ASVS:** V1, V3 (Web Frontend Security).
**Common CWEs:** CWE-79, CWE-601, CWE-1021.

Checklist:

- `dangerouslySetInnerHTML` — every call site re-justified; sanitizer (DOMPurify) applied with strict config.
- Hand-built DOM and non-React templates: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `v-html`, `srcdoc` fed by API data, URL parameters, or messages. Precedent 6 does not cover these.
- `window.location = userControlled`, `<a href={userControlled}>` without protocol allowlist (`javascript:`).
- `postMessage` listeners without `event.origin` check.
- Open redirect via `?next=` / router params.
- Service-worker registration scope.
- Hard-coded internal hostnames / dev tokens in bundled JS.

Per existing precedents: React/Angular are generally XSS-safe in the absence of the unsafe escape hatches above — do not flag generic JSX interpolation.

---

## L09 — C/C++ memory safety

**Scope predicate:** `language in {c, cpp}` AND `not is_test`.
**ASVS:** N/A (memory-safety lane, not in ASVS).
**Common CWEs:** CWE-119, CWE-125, CWE-787, CWE-190, CWE-416.

This is **in scope** for C/C++ even though the broader exclusion ("memory safety issues in memory-safe languages") still applies to Rust/Go/Python.

Checklist:

- Unchecked length fields in parser and decoder paths (including `protobuf-c`).
- Lifetime of borrowed `string_view` / `span` past the owner's scope, especially in hot paths that avoid copies.
- Integer truncation / overflow in size and offset arithmetic, allocator sizing.
- `memcpy` / `memmove` with attacker-influenced length.
- Off-by-one in loop bounds across buffer or chunk boundaries.
- TOCTOU on file paths in temp file handling.

---

## L10 — IaC / IAM (Terraform, jsonnet, kube)

**Scope predicate:** `role in {terraform, jsonnet, kube_manifest}` OR `trust_boundary == infrastructure_privilege`.
**ASVS:** V13 (Configuration).
**Common CWEs:** CWE-732, CWE-284.

Checklist:

- New IAM grants (GCP `roles/*` bindings, AWS IAM policies, Azure role assignments) — least privilege vs. what the code actually uses? (cross-ref the calling service's source).
- New service accounts or workload identities (GKE Workload Identity, EKS IRSA / Pod Identity, Azure Workload Identity) — what can the pod now do?
- Bucket / dataset permission widening: `allUsers`, `allAuthenticatedUsers`, `"Principal": "*"`, public datasets.
- Firewall rules: source-range `0.0.0.0/0` on non-public ports.
- Authoritative vs. additive resource pattern (e.g. on GCP, `google_project_iam_policy` overwrites; `google_project_iam_binding` is authoritative for the role; `google_project_iam_member` is additive — wrong choice can revoke unrelated bindings).
- Kube manifests: `hostNetwork`, `privileged`, `runAsUser: 0`, missing `securityContext`, `automountServiceAccountToken: true` on pods that don't need API access.
- Secrets in `ConfigMap` instead of `Secret`; Secret values committed.

---

## L11 — Supply chain (deps, Bazel, GHA)

**Scope predicate:** `len(deps_changed) > 0` OR `role in {bazel_build, gha_workflow}`.
**ASVS:** V15 (V15.2 Security Architecture & Dependencies), V13 (Configuration).
**Common CWEs:** CWE-829, CWE-1357.

Checklist:

- New dependencies in any manifest the inventory marks `dependency_manifest` (`package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Gemfile`, `pom.xml`, …): surface name + version. Do not attempt to judge maliciousness — that's SCA's job — but flag for human review with `severity: info`, `category: new_dependency`.
- Bazel `WORKSPACE` / `BUILD`: new `http_archive` without `sha256` pinning, new `git_repository` from an untrusted host.
- GHA workflows: `pull_request_target` + checkout of PR head + secrets exposure; `${{ github.event.* }}` interpolation into shell (script injection); unpinned action versions (`@main`, `@master`) on third-party actions.

---

## L12 — MCP tool boundary

**Scope predicate:** `role == mcp_tool` OR path matches `mcp|MCP`.
**ASVS:** V1 (Encoding & Sanitization), V2 (Validation & Business Logic), V4 (API & Web Service), V8 (Authorization).
**Common CWEs:** CWE-20, CWE-285.

Checklist (a new or modified MCP tool is an attacker-controlled trust boundary):

- Tool args validated against schema before reaching internal API.
- Tool output redaction / tenant-scope enforcement (does the tool ever return data from a tenant other than the caller's?).
- Tool composition: does combining two safe tools achieve a privileged effect (e.g. tool A returns a resource ID, tool B mutates by that ID without re-checking the caller owns it)?
- Tool description / system-prompt injection: tool descriptions sent to an LLM client cannot include attacker-controlled text from a database.

---

## L13 — External connectors (customer-supplied hosts)

Connectors where a customer supplies the destination host and credentials: data-warehouse and database integrations, webhooks, and similar outbound integrations.

**Scope predicate:** `trust_boundary == external_connector` OR path matches `warehouse|connectors?|webhooks?`.
**ASVS:** V1 (V1.3.6 SSRF), V12 (Secure Communication), V13 (V13.3 Secret Management), V16 (Security Logging & Error Handling).
**Common CWEs:** CWE-918 (SSRF — host IS attacker-controlled here), CWE-522, CWE-200.

Checklist:

- Hostname allowlist / blocklist: connections to private IP ranges (RFC1918, link-local, metadata IPs `169.254.169.254`) blocked?
- Credential storage at rest (KMS-encrypted? rotation?).
- Replay / idempotency on import jobs.
- Secret redaction in error paths — connector errors often include the connection string verbatim.
- Per-source query-injection: customer-controlled SQL fragments sent to _their_ warehouse — confirm the design intends this and there's no privilege confusion between the service's own identity and the customer's.

---

## L14 — Secure-by-design delta (diff-only)

**Scope predicate:** always runs if the inventory is non-empty.
**ASVS:** N/A (architectural lens).
**Framework:** OWASP Secure-by-Design Framework principles.

This agent reads only the diff plus relevant module READMEs. It produces findings of `category: design_concern` answering these five questions:

1. **Attack surface expansion** — does this PR add a new endpoint, deserializer, external call, file upload, or privilege? If yes, is that expansion justified and minimized?
2. **Secure defaults** — does the new feature require the operator to _opt into_ safety, or to _opt out of_ it? Defaults should be safe.
3. **Fail-mode** — on error/timeout/exception, does the code deny (fail closed) or allow (fail open)? Authorization paths must fail closed.
4. **Least privilege** — does any new credential, IAM binding, service account, or DB grant exceed what the code actually uses?
5. **Blast radius** — does the change create a cross-tenant, cross-service, or cross-environment dependency that previously didn't exist?

Findings here often lack a single line number — use `line_start: 0, line_end: 0` and put the explanation in `evidence_snippet` with a file list in `prerequisites`.
