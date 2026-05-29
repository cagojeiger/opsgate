# `me`

Milestone 1 surface:

```text
/mcp
```

Purpose: authenticated caller identity only. `me` does not return service
capabilities, credential summaries, credential aliases, endpoints, policies, or
secrets in Milestone 1.

## First-time setup

An MCP OAuth login proves the authgate identity, but opsgate still requires a
local `users` row. The first local user is created only by the browser login
flow:

1. Open the configured login URL once, usually `${OPSGATE_PUBLIC_URL}/login`.
2. Complete authgate OAuth as the configured `ADMIN_EMAIL` account.
3. Reconnect the MCP client to `RESOURCE_URL` (the MCP URL/audience).

If an authenticated MCP caller has no local opsgate user row yet, `/mcp`
returns HTTP `403` with `error="not_registered"` and onboarding URLs:

```json
{
  "error": "not_registered",
  "message": "This authgate account is authenticated but not registered in opsgate yet. Open login_url once, then reconnect your MCP client.",
  "login_url": "http://localhost:9091/login",
  "mcp_url": "http://localhost:9091/mcp"
}
```

The exact host is configuration-driven:

- `OPSGATE_PUBLIC_URL`: browser-facing opsgate origin used to build `login_url`.
- `RESOURCE_URL`: MCP resource/audience URL and returned `mcp_url`.
- `OAUTH_REDIRECT_URL`: callback URL registered in authgate for browser signup.

For GitOps production these should normally be the public `opsgate` domain; for
local development they may be `http://localhost:9091` and
`http://localhost:9091/mcp`.

## Input

```json
{}
```

## Output

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "sub": "authgate-subject",
  "email": "user@example.com",
  "name": "Display Name",
  "role": "admin",
  "is_admin": true
}
```

## Field contract

- `id`: local opsgate `users.id` UUID as a lowercase hyphenated string.
- `sub`: authgate subject.
- `email`: user email from the local opsgate row.
- `name`: `users.display_name`.
- `role`: request-scoped derived role (`ADMIN_EMAIL` override can promote a
  persisted `viewer` row to `admin`).
- `is_admin`: computed independently as `email == ADMIN_EMAIL`.

## Auth/error contract

- Missing or malformed Bearer token: HTTP `401` with `WWW-Authenticate` resource
  metadata discovery.
- Invalid token: HTTP `401`.
- Valid authgate token but no local user row: HTTP `403 not_registered` with
  `login_url` and `mcp_url`.
- Inactive local user: HTTP `403 inactive_user`.

Notes:

- `me` uses the same identity builder as REST `GET /api/v1/me`; REST and MCP
  output shapes are identical.
- `me` never performs token verification itself. Verification is shared through
  the single Bearer seam used by REST and MCP.
- Secrets, Bearer tokens, OAuth codes, PKCE verifiers, and raw Authorization
  headers are never returned or logged.
