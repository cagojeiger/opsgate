# `credential.update_http`

서피스:

```text
/mcp/admin
```

목적: 기존 `category=http` 자격 증명의 변경 가능한 메타데이터와 HTTP 정책을 갱신한다.

입력:

```json
{
  "alias": "prod-k8s",
  "reason": "Allow k8s self-review POST requests",
  "description": "Production Kubernetes API",
  "env": "prod",
  "tags": ["cluster", "prod"],
  "policy": {
    "allowed_methods": ["GET", "POST"],
    "allowed_path_prefixes": ["/api/v1", "/apis"],
    "denied_query_keys": ["watch"],
    "allowed_request_headers": ["Accept", "X-Request-Id"]
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
  "alias": "prod-k8s",
  "category": "http",
  "provider": "k8s",
  "env": "prod",
  "tags": ["cluster", "prod"],
  "description": "Production Kubernetes API",
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
- 봉인된 시크릿 헤더
- `tls_server_ca`
- `allow_private_network`

참고:

- `policy`는 병합이 아니라 전체 교체다.
- `reason`은 `update_reason`으로 기록된다.
- 감사 액션은 `mcp.credential.update`이다.
- 이력 액션은 `update`이다.
