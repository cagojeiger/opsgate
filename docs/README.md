# opsgate docs

이 디렉터리는 `0.1.0` release candidate에 맞춰 다시 정리하는 중입니다.

이전 문서 세트는 리포지토리 루트의 다음 위치에 보존되어 있습니다.

```text
docs.backup-20260520-170612/
```

현재 문서:

- [MCP tool surface specification index](mcp-tools.md)
- [api.call boundary model](mcp/api-call-boundary.md)
- [sql.query boundary model](mcp/sql-query-boundary.md)
- [MCP smoke report](mcp/smoke-report.md)
- [0.1.0 release readiness checklist](release-checklist.md)
- [MCP 도구 worst-case 설계와 TC 매트릭스](mcp/worst-cases.md)
- MCP surfaces:
  - [`/mcp` runtime](mcp/surfaces/runtime.md)
  - [`/mcp/admin` admin](mcp/surfaces/admin.md)
- MCP tools:
  - [me](mcp/tools/me.md)
  - [credential.list](mcp/tools/credential-list.md)
  - [credential.register_http](mcp/tools/credential-register-http.md)
  - [credential.update_http](mcp/tools/credential-update-http.md)
  - [credential.register_sql](mcp/tools/credential-register-sql.md)
  - [credential.update_sql](mcp/tools/credential-update-sql.md)
  - [credential.delete](mcp/tools/credential-delete.md)
  - [api.call](mcp/tools/api-call.md)
  - [sql.schema](mcp/tools/sql-schema.md)
  - [sql.query](mcp/tools/sql-query.md)

앞으로 추가할 문서:

- 데이터베이스 스키마와 audit/history 모델
- 보안 모델과 데이터 lifecycle
