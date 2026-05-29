# MCP smoke 리포트

날짜: 2026-05-21

범위:

```text
/mcp runtime surface
/mcp/admin admin surface
OAuth 2.1 bearer gate
runtime/admin tool list separation
credential lifecycle tools
api.call JSON envelope and policy gates
sql.query AST/output shape gates
wrong-tool audit/history metadata regression
```

실행 명령:

```text
go test ./internal/transport/http/server -run 'TestMCP_(RuntimeAndAdminToolSurfacesSmoke|OAuth21)' -count=1 -v
go test ./internal/transport/mcp/tools ./internal/service/http/call ./internal/service/sql/query ./internal/service/credentials -count=1 -v
go test ./internal/transport/http/server ./internal/transport/mcp/authz -count=1
```

결과:

```text
PASS
```

검증된 항목:

```text
/mcp/admin exposes:
  credential.delete
  credential.list
  credential.register_http
  credential.register_sql
  credential.update_http
  credential.update_sql
  me

/mcp exposes:
  api.call
  credential.list
  me
  sql.schema
  sql.query

non-admin bearer cannot use /mcp/admin
admin bearer can connect and call tools
credential.register_http does not leak endpoint/url/resolved_ips
credential.register_sql does not leak endpoint/url/username/password/resolved_ips
credential.update_http and credential.update_sql return ok through MCP
credential.list pagination and category filtering work through MCP
api.call returns a validated structured JSON output through MCP
sql.query output schema accepts non-row shapes
api.call wrong-category history keeps credential metadata snapshot
sql.query wrong-provider history keeps credential metadata snapshot
```

이 smoke가 다루지 않는 범위:

```text
external live authgate login flow
real Kubernetes API side effects
real Postgres query execution through a running local opsgate server
browser UI
```

비고:

```text
The smoke uses the real MCP SDK Streamable HTTP client against an in-memory
OAuth/resource-server stack. It validates wire-level tool registration,
auth middleware, MCP output schema validation, and service boundary behavior.
```
