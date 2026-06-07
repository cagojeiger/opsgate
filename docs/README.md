# opsgate 문서

이 디렉터리는 현재 Rust 구현과 맞는 문서만 유지합니다.

현재 문서:

- [MCP 도구/서피스 인덱스](mcp-tools.md)
- [MCP 도구 이름 규칙](mcp/tool-naming.md)
- [크레이트 경계와 의존성 설계](architecture/crate-boundaries.md)
- [인증 구조](architecture/auth.md)
- [api_call boundary 모델](mcp/api-call-boundary.md)
- [sql_query boundary 모델](mcp/sql-query-boundary.md)
- [릴리스 준비 체크리스트](release-checklist.md)
- [MCP 도구 최악 상황 방어 기준](mcp/worst-cases.md)
- MCP 서피스:
  - [`/mcp` runtime](mcp/surfaces/runtime.md)
  - [`/mcp/admin` admin](mcp/surfaces/admin.md)
- MCP 도구:
  - [me](mcp/tools/me.md)
  - [credential_list](mcp/tools/credential-list.md)
  - [credential_register_http](mcp/tools/credential-register-http.md)
  - [credential_update_http](mcp/tools/credential-update-http.md)
  - [credential_register_sql](mcp/tools/credential-register-sql.md)
  - [credential_update_sql](mcp/tools/credential-update-sql.md)
  - [credential_delete](mcp/tools/credential-delete.md)
  - [api_call](mcp/tools/api-call.md)
  - [sql_schema](mcp/tools/sql-schema.md)
  - [sql_query](mcp/tools/sql-query.md)
