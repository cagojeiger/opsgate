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
  "client_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "client_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "allow_private_network": false,
  "allow_insecure_transport": false
}
```

필수:

- `provider`
- `alias`
- `origin`
- `secret_headers` 또는 `client_cert_pem` + `client_key_pem`
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

- `origin`은 기본적으로 HTTPS여야 합니다. 내부 HTTP target은 `allow_private_network=true`와 `allow_insecure_transport=true`를 둘 다 켠 경우에만 허용됩니다. 내부망 허용은 SSRF/측면 이동 위험을 키우는 고위험 옵션이므로, 신뢰된 self-hosted/회사 내부 환경에서 필요한 alias에만 켭니다.
- `origin`에는 path/query/fragment/username/password를 포함할 수 없습니다. path 성격의 공통 prefix는 `base_path`에 넣습니다.
- `base_path`는 `/`로 시작해야 하며 `..`, `//`, query, fragment, CR/LF/NUL은 거부됩니다.
- `secret_headers`는 HTTP header 기반 target 인증입니다. mTLS-only target이면 빈 배열로 둘 수 있습니다.
- `client_cert_pem`/`client_key_pem`은 mTLS 기반 target 인증입니다. PEM은 HTTP header에 들어가지 않고 TLS handshake에서 client identity로 사용됩니다. `client_key_pem`은 매우 민감한 private key입니다. 봉인(sealed) 저장되지만 opsgate가 target 호출을 위해 런타임에 복호화하므로, opsgate 서버는 해당 private key의 수탁자가 됩니다. 운영 자동화에서는 가능하면 짧은 수명의 Bearer token/API key를 우선 사용하고, mTLS key 업로드는 신뢰된 self-hosted/폐쇄망 환경에서만 사용합니다.
- secret headers는 봉인(sealed)되며 절대 반환하지 않습니다.
- 호출자가 동적으로 보내는 header는 `policy.allowed_request_headers`에 등록되지
  않으면 거부됩니다.
- Auth, cookie, host, hop-by-hop, `X-Forwarded-*`, `Content-Type` header는
  계속 차단됩니다.
- `allow_insecure_transport=true`는 plain HTTP 허용용 고위험 옵션입니다. HTTPS 인증서 검증을 끄지 않으며, self-signed/private CA HTTPS target은 `tls_server_ca`를 제공해야 합니다.
- `allow_private_network=false`이면 private, loopback, link-local, 클라우드
  메타데이터 IP 대상을 차단합니다. 등록 시 DNS 검사와 런타임 target guard가 모두 적용됩니다.
- 봉인된 secret과 target(`origin`, `base_path`, TLS CA, client certificate/key)은 등록 후 변경할 수 없습니다. secret rotation이나 대상
  변경은 delete 후 재등록으로 처리하며, `credential.update_http`는 metadata와
  policy만 수정합니다.
