# `credential.update_sql`

서피스:

```text
/mcp/admin
```

목적: 기존 `category=sql` 자격 증명의 변경 가능한 메타데이터와 SQL 정책을 갱신한다.

입력:

```json
{
  "alias": "analytics-db",
  "reason": "Increase max_rows for compact status summaries",
  "policy": {
    "max_rows": 500,
    "max_bytes": 131072,
    "timeout_ms": 5000,
    "allow_metadata": true,
    "allow_explain": true,
    "allow_explain_analyze": false,
    "denied_functions": ["version"]
  }
}
```

필수:

- `alias`
- `reason`
- `description`, `env`, `tags`, `policy` 중 최소 하나

출력:

```json
{
  "alias": "analytics-db",
  "category": "sql",
  "provider": "postgres",
  "env": "prod",
  "tags": ["db", "analytics"],
  "description": "Analytics read model",
  "updated": true,
  "changed_fields": ["policy"]
}
```

변경 가능:

- `description`
- `env`
- `tags`
- `policy`

변경 불가:

- `alias`
- `category`
- `provider`
- `endpoint`
- username
- password

참고:

- `policy`는 병합이 아니라 전체 교체다.
- 시크릿 교체나 데이터베이스 대상 변경은 삭제 후 재등록이 필요하다.
- `reason`은 `update_reason`으로 기록된다.
- 감사 액션은 `mcp.credential.update`이다.
- 이력 액션은 `update`이다.
