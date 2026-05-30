# `me`

Surface:

```text
/mcp
/mcp/admin
```

Purpose: 호출자의 신원, 현재 surface에서 노출되는 capability 목록, 그리고 비밀이
아닌 credential 요약을 반환합니다.

Input:

```json
{}
```

Output:

```json
{
  "service": {
    "name": "opsgate",
    "purpose": "Policy-gated HTTP/SQL broker for LLM clients.",
    "secret_model": "...",
    "workflow": ["..."]
  },
  "capabilities": [
    {"tool": "credential.list", "description": "..."}
  ],
  "credential_summary": {
    "total": 3,
    "by_category": {"http": 2, "sql": 1},
    "by_provider": {"k8s": 2, "postgres": 1},
    "tags": {"prod": 2, "db": 1}
  },
  "id": "00000000-0000-0000-0000-000000000000",
  "sub": "...",
  "email": "...",
  "name": "..."
}
```

Notes:

- role/admin 개념은 반환하지 않습니다. Opsgate는 개인용 서비스이며 권한 경계는
  role이 아니라 surface별 툴 노출로 표현합니다.
- `/mcp`는 runtime 도구만 노출하고, `/mcp/admin`은 credential 관리 도구를
  노출합니다.
- alias는 반환하지 않습니다.
- endpoint는 반환하지 않습니다.
- secret은 반환하지 않습니다.
- `credential_summary`는 catalog의 대략적인 규모를 가늠하는 용도로만 사용하세요.
- 구체적인 alias와 policy는 `credential.list`로 확인하세요.
- runtime SQL 흐름은 `credential.list(category="sql")`로 시작하고, 테이블/컬럼
  이름을 모를 때 `sql.schema`를 거친 뒤 `sql.query`를 호출하는 순서입니다.
