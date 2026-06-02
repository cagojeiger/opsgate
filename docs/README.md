# opsgate 문서

이 디렉터리는 현재 Rust 구현과 맞는 문서만 유지합니다.

현재 문서:

- [MCP 도구/서피스 인덱스](mcp-tools.md)
- [크레이트 경계와 의존성 설계](architecture/crate-boundaries.md)
- [인증 구조](architecture/auth.md)
- [데이터 리텐션 정책](architecture/data-retention.md)
- [api.call boundary 모델](mcp/api-call-boundary.md)
- [sql.query boundary 모델](mcp/sql-query-boundary.md)
- [0.1.0 릴리스 준비 체크리스트](release-checklist.md)
- [MCP 도구 최악 상황 방어 기준](mcp/worst-cases.md)
- MCP 서피스:
  - [`/mcp` runtime](mcp/surfaces/runtime.md)
  - [`/mcp/admin` admin](mcp/surfaces/admin.md)
- MCP 도구:
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
