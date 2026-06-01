# MCP 도구 명세

opsgate `0.1.0` MCP 서피스의 인덱스 문서입니다.

opsgate는 LLM 클라이언트를 위한 policy-gated credential broker입니다. LLM은
credential의 alias, metadata, policy만 봅니다. opsgate는 secret과 target
URL 구성값을 숨긴 채, category별 전용 도구를 통해 HTTP 또는 SQL 호출을 대신
수행합니다.

## 서피스

- [Runtime 서피스: `/mcp`](mcp/surfaces/runtime.md)
- [Admin 서피스: `/mcp/admin`](mcp/surfaces/admin.md)

## 도구

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

## 일반적인 LLM 흐름

```text
1. me 호출
2. credential_summary 확인
3. category 필터로 credential.list 호출
4. metadata와 policy를 보고 alias 선택
5. SQL의 경우, table/column 이름을 모르면 먼저 sql.schema 호출
6. 간결한 purpose와 함께 api.call 또는 sql.query 호출
7. 거부되거나 truncate되면 policy/error/more hint를 보고 조정
```

## 가시성 모델

LLM에 보이는 것:

- alias
- category
- provider
- env
- tags
- description
- policy

숨겨지는 것:

- HTTP target 구성값(`origin`, `base_path`)
- Postgres `database_url`
- bearer token, API key, password, secret header 값
- request/response body history
- history에 남는 SQL parameter 값

SQL schema 조회는 SQL 데이터 조회와 분리되어 있습니다. `sql.schema`는
table/column/index 구조를 고정된 JSON으로 반환하며 row 값은 포함하지
않습니다. `sql.query`는 실제 쿼리 결과를 column-oriented JSON `body`로
반환하고, 큰 출력은 `api.call`과 같은 JSONPath/truncation 규칙을 따릅니다.

큰 HTTP/SQL JSON 응답은 full body를 받기보다 `api.call.jsonpath` 또는
`sql.query.jsonpath`로 필요한 값만 뽑는 것을 우선합니다. JSONPath는 표준 selection grammar를 기본으로 하며,
개수 질문에는 `.length()`/`.count()` suffix로 작은 숫자만 반환할 수 있습니다.

응답 truncation, preview, 토큰 예산 규칙은
[JSON 출력과 토큰 예산 스펙](mcp/json-output.md)에 정의합니다.

도구별 최악의 경우와 현재 방어 기준은
[MCP 도구 최악 상황 방어 기준](mcp/worst-cases.md)에 정의합니다.

`api.call` 고유의 닫힌 boundary 모델은
[api.call boundary 모델](mcp/api-call-boundary.md)에 정의합니다.

`sql.query` 고유의 닫힌 boundary 모델은
[sql.query boundary 모델](mcp/sql-query-boundary.md)에 정의합니다.
