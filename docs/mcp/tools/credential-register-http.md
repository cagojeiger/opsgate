# `credential.register_http`

Surface:

```text
/mcp/admin
```

Purpose: 이후 `api.call`에서 사용할 HTTPS API credential을 등록합니다.

Input:

```json
{
  "provider": "k8s",
  "alias": "prod-k8s",
  "endpoint": "https://example.invalid",
  "secret_headers": [
    {"name": "Authorization", "value": "Bearer ..."}
  ],
  "description": "Production Kubernetes API",
  "env": "prod",
  "tags": ["cluster", "prod"],
  "policy": {
    "allowed_methods": ["GET", "POST"],
    "allowed_path_prefixes": ["/api/v1", "/apis"],
    "denied_query_keys": ["watch"],
    "allowed_request_headers": ["Accept", "X-Request-Id"]
  },
  "tls_server_ca": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "allow_private_network": false
}
```

Required:

- `provider`
- `alias`
- `endpoint`
- `secret_headers`
- `policy`

Output:

```json
{
  "alias": "prod-k8s",
  "category": "http",
  "provider": "k8s",
  "env": "prod",
  "tags": ["cluster", "prod"],
  "description": "Production Kubernetes API",
  "created": true
}
```

Rules:

- `endpoint`는 HTTPS여야 합니다.
- endpoint의 query와 fragment는 거부됩니다.
- secret headers는 봉인(sealed)되며 절대 반환하지 않습니다.
- 호출자가 동적으로 보내는 header는 `policy.allowed_request_headers`에 등록되지
  않으면 거부됩니다.
- Auth, cookie, host, hop-by-hop, `X-Forwarded-*`, `Content-Type` header는
  계속 차단됩니다.
- `allow_private_network=false`이면 private, loopback, link-local, 클라우드
  메타데이터 IP 대상을 차단합니다(등록 시 DNS 검사로 검증).
- 봉인된 secret/endpoint는 등록 후 변경할 수 없습니다. secret rotation이나 대상
  변경은 delete 후 재등록으로 처리하며, `credential.update_http`는 metadata와
  policy만 수정합니다.
