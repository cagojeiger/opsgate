# `credential_register_sql`

서피스:

```text
/mcp/admin
```

목적: 이후 `sql_query`에서 사용할 Postgres credential을 등록합니다.

입력:

```json
{
  "provider": "postgres",
  "alias": "analytics-db",
  "database_url": "postgres://db.example.invalid:5432/analytics?sslmode=require",
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
  "allow_private_network": false,
  "allow_insecure_transport": false
}
```

필수:

- `alias`
- `database_url`
- `username`
- `password`

선택값이지만 중요한 필드:

- `policy`: 생략하면 기본 policy를 사용합니다.

출력:

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

규칙:

- `provider`의 기본값은 `postgres`입니다.
- `policy={}`는 유효합니다.
- `database_url`은 기본 데이터베이스와 고정된 서버(host/port/options)를 선택합니다. `sql_schema`/`sql_query`의 `database` 옵션으로 같은 서버의 다른 DB를 선택할 수 있지만 host/port/user/password는 바뀌지 않습니다.
- `database_url`에는 username이나 password를 포함하면 안 됩니다.
- username/password는 봉인(sealed)되며 절대 반환하지 않습니다.
- opsgate는 서버(host/port)와 계정(username/password)을 credential 등록 시점에 고정하고,
  호출 시에는 같은 서버 안의 데이터베이스 이름만 선택할 수 있게 합니다.
- 데이터 도달 범위는 DB role grant로 제어합니다. 하나의 credential로 여러 DB를 조회하려면 해당 role에 각 DB의 읽기 권한이 있어야 합니다.
- SQL policy는 row/byte/timeout, metadata, EXPLAIN, denied function 동작을
  제어합니다.
- 기본적으로 `sslmode=require`가 필요합니다. 내부/비TLS 연결은 `allow_private_network=true`와 `allow_insecure_transport=true`를 둘 다 켠 경우에만 허용됩니다.
- 봉인된 secret과 target `database_url`은 등록 후 변경할 수 없습니다. secret rotation이나
  데이터베이스 대상 변경은 delete 후 재등록으로 처리하며,
  `credential_update_sql`은 metadata와 policy만 수정합니다.
