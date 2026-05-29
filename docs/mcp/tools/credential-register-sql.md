# `credential.register_sql`

Surface:

```text
/mcp/admin
```

Purpose: 이후 `sql.query`에서 사용할 Postgres credential을 등록합니다.

Input:

```json
{
  "provider": "postgres",
  "alias": "analytics-db",
  "endpoint": "postgres://db.example.invalid:5432/analytics?sslmode=require",
  "username": "readonly_user",
  "password": "...",
  "description": "Analytics read model",
  "env": "prod",
  "tags": ["db", "analytics"],
  "policy": {
    "max_rows": 100,
    "max_bytes": 65536,
    "timeout_ms": 3000,
    "allow_metadata": false,
    "allow_explain": false,
    "allow_explain_analyze": false,
    "denied_functions": []
  },
  "allow_private_network": false
}
```

Required:

- `alias`
- `endpoint`
- `username`
- `password`
- `policy`

Output:

```json
{
  "alias": "analytics-db",
  "category": "sql",
  "provider": "postgres",
  "env": "prod",
  "tags": ["db", "analytics"],
  "description": "Analytics read model",
  "created": true
}
```

Rules:

- `provider`의 기본값은 `postgres`입니다.
- `policy={}`는 유효합니다.
- endpoint가 데이터베이스 경계를 선택합니다.
- endpoint에는 username이나 password를 포함하면 안 됩니다.
- username/password는 봉인(sealed)되며 절대 반환하지 않습니다.
- opsgate는 일반적인 데이터 경계로 LLM에게 데이터베이스 schema를 고르게 하지
  않습니다.
- 데이터 도달 범위는 endpoint의 데이터베이스와 DB role grant로 제어합니다.
- SQL policy는 row/byte/timeout, metadata, EXPLAIN, denied function 동작을
  제어합니다.
- 봉인된 secret/endpoint는 등록 후 변경할 수 없습니다. secret rotation이나
  데이터베이스 대상 변경은 delete 후 재등록으로 처리하며,
  `credential.update_sql`은 metadata와 policy만 수정합니다.
