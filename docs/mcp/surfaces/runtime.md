# `/mcp` runtime 서피스

목적: 기존 자격 증명 사용.

툴:

```text
me
credential_list
api_call
sql_schema
sql_query
```

LLM이 비밀이 아닌 자격 증명 메타데이터를 조회하고, alias를 통해 HTTP API나
Postgres 데이터베이스를 호출해야 할 때 이 서피스를 사용한다.

규칙:

- 자격 증명 라이프사이클 관리 툴은 여기에 마운트되지 않는다.
- `api_call`은 `category=http`가 필요하다.
- `sql_schema`는 `category=sql`이 필요하며 구조만 반환한다.
- `sql_query`는 `category=sql`이 필요하다.
- `credential_list`는 메타데이터와 정책만 반환하며, 시크릿이나 엔드포인트는
  절대 반환하지 않는다.
- `api_call`, `sql_schema`, `sql_query`는 `purpose`가 필요하다.

전형적인 흐름:

```text
me
credential_list(category=http|sql)
api_call or sql_schema -> sql_query
```
