# MCP 도구 이름 규칙

MCP 도구 이름은 Claude/Frontend remote MCP validator가 허용하는 다음 패턴을
따릅니다.

```text
^[a-zA-Z0-9_-]{1,64}$
```

따라서 opsgate의 MCP 도구 이름은 `snake_case`를 사용합니다. 점(`.`), 슬래시(`/`),
공백은 사용하지 않습니다.

## 현재 도구 이름

Runtime `/mcp`:

```text
me
credential_list
api_call
sql_schema
sql_query
```

Admin `/mcp/admin`:

```text
me
credential_list
credential_register_http
credential_register_sql
credential_update_http
credential_update_sql
credential_delete
```

## 이전 이름과 현재 이름

초기 prototype에서는 dotted name을 사용했습니다. 현재는 호환성을 위해 모두
`snake_case`로 바꿉니다.

| 이전 | 현재 |
|---|---|
| `credential.list` | `credential_list` |
| `api.call` | `api_call` |
| `sql.schema` | `sql_schema` |
| `sql.query` | `sql_query` |
| `credential.register_http` | `credential_register_http` |
| `credential.register_sql` | `credential_register_sql` |
| `credential.update_http` | `credential_update_http` |
| `credential.update_sql` | `credential_update_sql` |
| `credential.delete` | `credential_delete` |

## 감사 로그 이름과의 차이

MCP 도구 이름과 내부 감사 action 이름은 같은 개념이 아닙니다.

- MCP 도구 이름: 클라이언트가 보는 tool schema의 `name`입니다. 위 regex를 반드시
  만족해야 합니다.
- 감사 action/event 이름: DB와 로그의 taxonomy입니다. 기존 `mcp.api.call` 같은
  dotted action은 도구 schema name이 아니므로 이 규칙의 대상이 아닙니다.

즉 외부 MCP tool name은 `api_call`이지만, 기존 감사 action은 `mcp.api.call`처럼
남을 수 있습니다.
