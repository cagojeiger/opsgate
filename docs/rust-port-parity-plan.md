# Rust Port Parity Execution Plan

This plan tracks the work to bring the Rust port in this repository back to
feature-layer parity with the Go source repository at
`/Users/kangheeyong/project/opsgate-jelly`.

## Scope

Source of truth:
- Go repository: `/Users/kangheeyong/project/opsgate-jelly`
- Rust repository: `/Users/kangheeyong/project/opsgate`

Goal:
- Restore behaviorally important parity across auth, admin boundaries, REST
  API, OAuth discovery, credential lifecycle, SQL policy, persistence,
  auditability, and release validation.

Non-goals:
- Do not rewrite the Rust port into Go-style module structure.
- Do not convert Rust UUID primary keys back to Go BIGSERIAL ids unless a
  separate data compatibility requirement is established.
- Do not reset or destroy existing Rust database data.
- Do not add new product features beyond the parity gaps already identified.

## Assumptions

- The Go repo is the parity baseline unless a Rust-specific design decision is
  already documented.
- Existing Rust database deployments may contain data, so schema work should
  use forward migrations instead of editing old migrations.
- The main agent owns commits. Subagents may inspect, propose patches, or work
  in bounded lanes, but the main agent reviews, integrates, verifies, stages,
  and commits.
- Every implementation phase ends with one focused commit. No next phase starts
  until the previous phase has verification evidence and a commit.
- No new external mutation surface may be exposed before service-level role
  authorization and credential validation/history parity are in place.
- Phase commits are checkpoints, not all independently production-deployable.
  The final deploy gate is after runtime DB least privilege and audit coverage
  are restored.

## Execution Model

Before each phase:
- Check `git status --short`.
- Re-read the touched Go and Rust files for that phase.
- Spawn bounded agents only for independent work:
  - `explorer`: map affected files and parity details.
  - `worker`: implement a disjoint patch lane when the write set is isolated.
  - `verifier` or `code-reviewer`: review the diff and test coverage.

During each phase:
- Keep changes surgical and scoped to the phase.
- Prefer Rust workspace patterns already present in `backend/crates/*`.
- Preserve existing user changes if the worktree becomes dirty.

After each phase:
- Run the phase-specific tests plus the common verification set.
- Stage only files belonging to the phase.
- Commit with a focused message.
- Continue to the next phase only after the commit succeeds.

Common verification set:
- `cargo fmt --all --check`
- `cargo check --workspace`
- `cargo test --workspace`
- When touching lint-sensitive code: `cargo clippy --all-targets --all-features -- -D warnings`

## Phase 0: Commit This Plan

Target commit:
- `docs: add Rust port parity execution plan`

Acceptance criteria:
- This file exists in `docs/`.
- Plan has phase boundaries, verification gates, and commit boundaries.
- Architect and critic review have no blocking objections.

Verification:
- `git diff -- docs/rust-port-parity-plan.md`

## Phase 1: Role Authorization Contract and Admin Boundary

Target commit:
- `auth: restore role authorization boundary`

Go evidence:
- Go admin MCP mount requires `RequireRole("admin")`.
- Go identity resolver derives admin role from `ADMIN_EMAIL`.
- Go caller carries role, request id, remote IP, and user agent.
- Go credential register/delete require admin at the service layer.
- Go `api.call`, `sql.query`, and `sql.schema` deny viewer callers.

Rust gap:
- Rust `User` and `Caller` have no role.
- Rust `/mcp/admin` uses the same bearer verification as runtime `/mcp`.
- Rust browser login upserts any OIDC user.
- Rust execution and credential services mostly accept `owner_user_id`, so REST
  or MCP callers can bypass role checks if handlers are mounted incorrectly.

Implementation outline:
- Add config support for `OPSGATE_ADMIN_EMAIL`.
- Touchpoints to update explicitly:
  - `opsgate_core::Config`;
  - identity `Resolver::new` and role derivation;
  - `UserRepo` row mapping;
  - bearer middleware and MCP verifier;
  - `me` output;
  - service method signatures that currently accept only `owner_user_id`.
- Add a forward DB migration for role compatibility:
  - add nullable lifecycle columns directly;
  - add `role TEXT NOT NULL DEFAULT 'viewer'` with an
    `admin/operator/viewer` check constraint;
  - backfill existing rows to `viewer`;
  - update `audit_logs.actor_role` and `sql_query_history.actor_role`
    constraints from Rust's current role vocabulary to `admin/operator/viewer`;
  - before replacing those constraints, migrate existing legacy
    `actor_role = 'active'` rows to the conservative compatible value
    `viewer`, and preserve existing `admin` rows as `admin`;
  - add missing `actor_role` and `request_id` columns to `api_call_history`;
  - adjust history/audit repo structs and recorders so the new role taxonomy can
    be inserted before role-aware services are enabled;
  - keep request-scoped admin override from `OPSGATE_ADMIN_EMAIL`.
- Extend Rust domain identity with `Role` and role-aware `Caller`.
- Extend `Caller` with request id, remote IP, and user agent so later audit work
  can flow through without another identity rewrite.
- Make browser signup reject non-admin email.
- Make API/MCP lookup derive request-scoped admin role from config.
- Add explicit `/mcp/admin` role enforcement.
- Add service-level authorization helpers:
  - credential register/update/delete require admin;
  - `api.call`, `sql.query`, and `sql.schema` require operator or admin;
  - `credential.list` and `me` remain available to registered active users.
- Update MCP tools to pass `Caller`, not just `caller.user.id`, into services
  that need role decisions.
- Add critical auth audit rows for browser signup denied/success and MCP admin
  role denial; broader request/tool audit is handled in Phase 7.

Acceptance criteria:
- A non-admin registered user can call runtime `/mcp` but cannot call
  `/mcp/admin`.
- Only `OPSGATE_ADMIN_EMAIL` can complete browser signup.
- `me` output reflects the actual request role instead of endpoint-derived
  admin status.
- Viewer callers are denied for `api.call`, `sql.query`, and `sql.schema`.
- Credential mutation is admin-only regardless of REST or MCP entrypoint.
- Denied admin access is test-covered.

Verification:
- Unit tests for identity resolver role derivation and admin allowlist.
- Route/MCP auth tests for runtime allowed and admin denied.
- Service tests for admin-only credential mutation and viewer-denied execution.
- Tests that `operator` is allowed for `api.call`, `sql.query`, and
  `sql.schema`, while `viewer` is denied and `admin` remains allowed.
- Audit/history persistence tests that insert `admin`, `operator`, and
  `viewer` roles after the role constraint migration.
- Migration rehearsal with existing `actor_role = 'active'` rows in
  `audit_logs` and `sql_query_history`, proving they are converted before the
  new constraints are enforced.
- Common verification set.

## Phase 2: Credential Validation, Search, and History

Target commit:
- `credentials: restore validation and lifecycle history parity`

Go evidence:
- Go validates provider, alias, env, tags, q length, field count, cursor, and
  list fields.
- Go `q` searches alias, description, category, provider, env, and tags.
- Go writes per-owner alias history versions for register, update, and delete.
- Go tracks created_by, updated_by, deleted_by.

Rust gap:
- Rust validation is looser.
- Rust `q` only searches alias and description.
- Rust has `credential_audit_events`, but not Go-style versioned
  `credential_history`.
- Rust credentials do not track actor columns.

Implementation outline:
- Add validation parity for provider, alias, env, tags, q, fields, cursor, and
  max tag count.
- Expand Rust list search to category, provider, env, and tags.
- Add a data-preserving forward migration:
  - add `created_by`, `updated_by`, `deleted_by` as nullable columns;
  - backfill `created_by` and `updated_by` from `owner_user_id`;
  - backfill `deleted_by = owner_user_id` for already soft-deleted rows where
    `deleted_at IS NOT NULL`;
  - then set `created_by` and `updated_by` to NOT NULL;
  - keep `deleted_by` nullable and paired with `deleted_at`;
  - update the delete repository path in the same phase so future deletes set
    `deleted_by` before adding or validating the pair constraint;
  - add `secret_destroyed_at` constraints only after existing rows are
    compatible;
  - add `credential_history` with unique `(owner_user_id, alias, version)`.
- Write history rows transactionally with credential changes.
- Keep secret ciphertext and endpoint out of history/audit.

Acceptance criteria:
- Invalid provider/alias/env/tag/q/field/cursor inputs are rejected.
- Credential search matches Go-visible fields.
- Register/update/delete produce monotonic per-owner alias history versions.
- Actor columns are populated for mutable credential operations.

Verification:
- Credential validation tests.
- Repository tests for list search and history versioning.
- Migration tests or an equivalent local migration rehearsal against a
  non-empty Rust database containing active and soft-deleted credentials.
- Common verification set.

## Phase 3: Runtime Database Least Privilege

Target commit:
- `db: restore runtime database least privilege`

Go evidence:
- Go separates migration DSN and runtime DSN.
- Go baseline creates and grants a narrowed `opsgate_app` role.

Rust gap:
- Rust config and compose use one `OPSGATE_DATABASE_URL`.
- Rust app runs migrations and runtime queries through the same pool.

Implementation outline:
- Add `OPSGATE_DATABASE_MIGRATE_URL`.
- Run embedded migrations through the migrate pool.
- Open the runtime pool with `OPSGATE_DATABASE_URL`.
- Add a cumulative grant migration for all current tables, sequences, and types
  needed by the runtime role after Phase 1 and Phase 2 schema changes.
- Create `opsgate_app` if missing.
- Grant only required table and column permissions to `opsgate_app`.
- Do not grant runtime updates to protected identity columns such as
  `users.role`.
- Update compose and `.env.example`.
- Keep local development defaults explicit and non-secret.

Acceptance criteria:
- Migrations can run as the owner role.
- Runtime service can operate with the narrowed app role.
- Runtime role cannot perform schema-owner operations.

Verification:
- Config tests for both DSNs.
- Integration test or documented smoke test with compose using `opsgate_app`.
- Least-privilege smoke that proves `opsgate_app` can run normal service
  operations but cannot `ALTER TABLE`, create tables, or update protected role
  columns.
- Common verification set.

## Phase 4: REST API Surface Parity

Target commit:
- `rest: restore API execution and credential endpoints`

Go evidence:
- Go REST mounts:
  - `GET /api/v1/me`
  - `POST /api/v1/api/call`
  - `POST /api/v1/sql/query`
  - `POST /api/v1/credentials`
  - `GET /api/v1/credentials`
  - `DELETE /api/v1/credentials/{alias}`

Rust gap:
- Rust REST currently exposes only `/api/v1/me`.

Implementation outline:
- Add Rust REST handlers that call the existing services for:
  - `api.call`
  - `sql.query`
  - one Go-compatible `POST /api/v1/credentials` DTO with `category` and
    category-specific `secret`;
  - credential list;
  - credential delete.
- The unified REST credential create DTO should follow Go's shape:
  `{category, provider, alias, endpoint, secret, description, env, tags,
  policy, allow_private_network, tls_server_ca}` and dispatch internally to the
  existing HTTP or SQL registration service input.
- Do not add REST credential update unless separate evidence shows Go REST
  supported it.
- Use the Phase 1 service-level authorization contract so REST credential
  mutation cannot bypass admin checks.
- Add REST request audit middleware or service-level audit for REST requests.
- Reuse existing bearer middleware and error envelope patterns.

Acceptance criteria:
- All Go REST routes listed above exist in Rust.
- REST and MCP execution services share the same policy behavior.
- REST handlers do not expose secrets, raw target bodies, SQL params, or result
  rows in audit/history.
- Invalid bearer, unregistered user, and unauthorized role behavior match the
  restored identity model.

Verification:
- REST route tests for success and auth failure paths.
- Service tests reused where possible.
- Common verification set.

## Phase 5: OAuth Discovery and Challenge Compatibility

Target commit:
- `auth: restore OAuth discovery compatibility`

Go evidence:
- Go exposes `/.well-known/oauth-authorization-server`.
- Go serves exact and wildcard protected-resource metadata paths.
- Go appends `scope="openid offline_access"` to bearer challenges.

Rust gap:
- Rust only exposes protected-resource metadata.
- Rust challenge only includes `resource_metadata`.

Implementation outline:
- Add authorization-server metadata response at the Rust origin.
- Add wildcard protected-resource metadata route for resource paths.
- Append the scope hint to `WWW-Authenticate` bearer challenges.
- Keep existing protected-resource metadata fields.

Acceptance criteria:
- `/.well-known/oauth-authorization-server` returns issuer, authorization,
  token, revocation, grant, PKCE, and public-client metadata.
- `/.well-known/oauth-protected-resource` and path-qualified variants work.
- Unauthenticated MCP responses include both `resource_metadata` and
  `scope="openid offline_access"`.

Verification:
- Metadata unit/route tests.
- Challenge header tests.
- Common verification set.

## Phase 6: SQL Policy Parity

Target commit:
- `sql: restore metadata function policy parity`

Go evidence:
- Go rejects `pg_catalog` and `information_schema` function schemas unless
  `allow_metadata` is enabled.
- Go checks both unqualified and fully qualified denied functions.

Rust gap:
- Rust function checks mostly inspect the last object-name segment.

Implementation outline:
- Preserve the current Rust AST visitor structure.
- Add function schema inspection for metadata schemas.
- Ensure fully qualified and unqualified denied functions are both checked.
- Add regression tests for non-denylisted `pg_catalog.*` function calls.

Acceptance criteria:
- Metadata-schema function calls are denied unless `allow_metadata=true`.
- Existing builtin risky function denylist still applies.
- Existing allowed SELECT/WITH/EXPLAIN behavior is preserved.

Verification:
- SQL policy unit tests.
- Common verification set.

## Phase 7: Audit and Observability Parity

Target commit:
- `audit: restore auth and request audit parity`

Go evidence:
- Go audits REST request attempts, MCP auth denials, signup denials/success, and
  tool calls with request metadata.
- Go caller carries request id, remote IP, and user agent into audit rows.

Rust gap:
- Rust tracing logs some auth failures, but DB audit rows are incomplete.
- Even after Phase 1 adds caller metadata fields, the remaining services and
  middleware need to persist those fields consistently.

Implementation outline:
- Complete propagation of request id, remote IP, user agent, and role into
  service audit rows.
- Update the concrete audit/history touchpoints:
  - `api_call_history` repo and recorder;
  - `sql_query_history` repo and recorder;
  - `audit_logs` repo and event constructors;
  - REST bearer middleware and request audit middleware;
  - MCP auth response path;
  - MCP tool audit helper;
  - browser login/callback audit path;
  - credential lifecycle audit/history writers.
- Add remaining audit rows for REST request audit, MCP non-admin auth denials,
  and MCP tool calls where Rust behavior still trails Go.
- Keep audit failures non-fatal where Go treats them as best-effort.

Acceptance criteria:
- Denied auth and signup events are persisted without secrets.
- REST requests produce audit rows with route/action context.
- MCP tool calls and auth denials include request metadata.

Verification:
- Audit repository/service tests.
- Auth route tests asserting audit sink calls where feasible.
- Common verification set.

## Phase 8: Release, Smoke, and Documentation Parity

Target commit:
- `docs: update Rust release and smoke checks`

Go evidence:
- Go has `release-check`, integration test, metadata curl, MCP smoke coverage,
  and docs describing those checks.

Rust gap:
- Rust docs still reference Go commands and old `internal/...` paths.
- Rust lacks equivalent top-level release/smoke workflow documentation.

Implementation outline:
- Update `docs/release-checklist.md` for Rust commands.
- Update `docs/mcp/smoke-report.md` with Rust test commands and live smoke
  expectations.
- Add a top-level `Makefile` or equivalent script only if it removes real
  repetition and matches the repo style.
- Document compose-based OAuth/MCP smoke steps.

Acceptance criteria:
- Docs no longer refer to Go-only commands for this Rust repo.
- Release checklist maps to commands that actually exist.
- Smoke docs cover metadata, unauthenticated MCP challenge, runtime/admin tool
  surfaces, and REST routes.

Verification:
- Run documented local commands where environment permits.
- Common verification set.

## Phase 9: Final Parity Review

Target commit:
- `chore: record Rust parity review`

Implementation outline:
- Re-run a fresh feature-layer comparison against the Go repo.
- Use at least one verifier/code-reviewer agent against the final diff.
- Record remaining intentional divergences.

Acceptance criteria:
- All high-confidence gaps from the initial comparison are either fixed or
  explicitly documented as intentional differences.
- Final verification passes or has documented environment-only gaps.

Verification:
- Common verification set.
- Compose smoke test if local services are available.
- Final `git log --oneline` shows one commit per phase.

## Known Decisions

- Preserve Rust UUID primary keys unless a separate migration compatibility
  requirement is provided.
- Prefer forward migrations over rewriting existing Rust migrations.
- Restore Go behavior at the feature boundary, not necessarily exact internal
  implementation details.
- Commit after each completed phase; do not batch multiple layers into one
  large commit.

## Open Questions

- Are existing Rust database volumes disposable? If yes, schema work could be
  simpler, but this plan assumes data preservation.
- Should Rust intentionally keep MCP-only admin mutation and omit REST update
  endpoints? Current Go evidence supports REST create/list/delete, not REST
  update.
- Should the final parity review produce a permanent user-facing matrix in
  `docs/`, or only a commit summary?
