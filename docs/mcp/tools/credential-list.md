# `credential.list`

Surface:

```text
/mcp
/mcp/admin
```

Purpose: discovery를 위해 호출자가 볼 수 있는 활성 credential을 나열합니다.

Input:

```json
{
  "category": "http",
  "provider": "k8s",
  "env": "prod",
  "tag": "cluster",
  "q": "osaka",
  "fields": ["category", "provider", "env", "tags", "policy"],
  "limit": 50,
  "cursor": "..."
}
```

모든 필드는 선택값입니다. `q`는 alias, description, category, provider, env,
tags를 대상으로 검색합니다.

Output:

```json
{
  "credentials": [
    {
      "alias": "prod-k8s",
      "category": "http",
      "provider": "k8s",
      "description": "Production Kubernetes API",
      "env": "prod",
      "tags": ["cluster", "prod"],
      "policy": {
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/api/v1"],
        "denied_query_keys": ["watch"],
        "allowed_request_headers": []
      }
    }
  ],
  "page": {
    "limit": 50,
    "returned": 1,
    "has_more": false,
    "next_cursor": "..."
  }
}
```

Rules:

- `alias`는 항상 반환됩니다.
- secret은 절대 반환하지 않습니다.
- endpoint는 절대 반환하지 않습니다.
- 삭제된 credential은 반환하지 않습니다.
- 호출자 본인의 credential만 보이며, 다른 사용자의 credential은 볼 수 없습니다.
- `limit`의 기본값은 50이며 최대 100으로 제한됩니다.
- 다음 페이지를 요청할 때는 직전 응답의 `page.next_cursor`를 `cursor`로 넘깁니다.
- `page.next_cursor`는 `page.has_more=true`일 때만 포함됩니다.
- `fields`는 반환되는 metadata를 제한하지만 `alias`는 제거할 수 없습니다.
