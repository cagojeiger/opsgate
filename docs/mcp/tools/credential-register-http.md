# `credential.register_http`

서피스:

```text
/mcp/admin
```

목적: 이후 `api.call`에서 사용할 HTTP API credential을 등록합니다. LLM에는 전체 target URL을 노출하지 않고, 등록된 `origin`과 숨겨진 `base_path`에 런타임 `request_path`를 붙여 호출합니다.

입력:

```json
{
  "provider": "k8s",
  "alias": "prod-k8s",
  "origin": "https://example.invalid",
  "base_path": "/cluster-a",
  "secret_headers": [
    {"name": "Authorization", "value": "Bearer ..."}
  ],
  "description": "Production Kubernetes API",
  "env": "prod",
  "tags": ["cluster", "prod"],
  "policy": {
    "allowed_methods": ["GET", "POST"],
    "allowed_request_path_prefixes": ["/api/v1", "/apis"],
    "denied_query_keys": ["watch"],
    "allowed_request_headers": ["Accept", "X-Request-Id"]
  },
  "tls_server_ca": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "allow_private_network": false,
  "allow_insecure_transport": false
}
```

필수:

- `provider`
- `alias`
- `origin`
- `secret_headers`
- `policy`

선택값이지만 중요한 필드:

- `base_path`: target origin 뒤에 항상 붙는 숨겨진 기본 경로입니다. 생략하면 `/`입니다. 예를 들어 `base_path=/cluster-a`, `api.call.request_path=/api/v1/pods`이면 실제 호출 경로는 `/cluster-a/api/v1/pods`입니다.

출력:

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

규칙:

- `origin`은 기본적으로 HTTPS여야 합니다. 내부 HTTP target은 `allow_private_network=true`와 `allow_insecure_transport=true`를 둘 다 켠 경우에만 허용됩니다.
- `origin`에는 path/query/fragment/username/password를 포함할 수 없습니다. path 성격의 공통 prefix는 `base_path`에 넣습니다.
- `base_path`는 `/`로 시작해야 하며 `..`, `//`, query, fragment, CR/LF/NUL은 거부됩니다.
- secret headers는 봉인(sealed)되며 절대 반환하지 않습니다.
- 호출자가 동적으로 보내는 header는 `policy.allowed_request_headers`에 등록되지
  않으면 거부됩니다.
- Auth, cookie, host, hop-by-hop, `X-Forwarded-*`, `Content-Type` header는
  계속 차단됩니다.
- `allow_private_network=false`이면 private, loopback, link-local, 클라우드
  메타데이터 IP 대상을 차단합니다. 등록 시 DNS 검사와 런타임 target guard가 모두 적용됩니다.
- 봉인된 secret과 target(`origin`, `base_path`, TLS CA)은 등록 후 변경할 수 없습니다. secret rotation이나 대상
  변경은 delete 후 재등록으로 처리하며, `credential.update_http`는 metadata와
  policy만 수정합니다.
