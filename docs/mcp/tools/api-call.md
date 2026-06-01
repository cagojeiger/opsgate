# `api.call`

서피스:

```text
/mcp
```

목적: `category=http` credential을 통해 등록된 HTTP API를 호출합니다. 호출자는 전체 target URL을 보지 않고 `request_path`만 제공합니다.

응답 truncation, JSONPath projection, 토큰 예산 규칙은
[JSON 출력과 토큰 예산 스펙](../json-output.md)에 정의합니다.

입력:

```json
{
  "alias": "prod-k8s",
  "purpose": "Check pod phases before summarizing cluster health",
  "method": "GET",
  "request_path": "/api/v1/pods",
  "query": {"limit": "100"},
  "headers": {"Accept": "application/json"},
  "body": null,
  "content_type": "",
  "jsonpath": ["$.items[*].metadata.name", "$.items[*].status.phase"],
  "max_bytes": 4096
}
```

필수:

- `alias`
- `purpose`
- `request_path`

제약:

- `purpose`는 8~512자이며 CR/LF를 포함할 수 없습니다.
- `max_bytes` 허용 범위는 256~1048576입니다.
- query key는 최대 32개, key 길이는 최대 128자, value 길이는 최대 4096자입니다.
- query key/value는 CR/LF와 NUL을 포함할 수 없습니다.

기본값:

- `method=GET`
- `max_bytes=4096`
- policy가 override를 허용하지 않는 한 JSON `Accept`가 자동으로 전송됩니다.
- non-GET JSON body는 기본적으로 `Content-Type: application/json`을 사용합니다.

출력:

```json
{
  "status_code": 200,
  "headers": {"content-type": "application/json"},
  "body": {
    "$.items[*].metadata.name": ["api", "worker"],
    "$.items[*].status.phase": ["Running", "Running"]
  },
  "truncated": false,
  "original_bytes": 420,
  "returned_bytes": 420,
  "latency_ms": 34
}
```

규칙:

- credential은 `category=http`여야 합니다.
- alias는 존재하지만 다른 category에 속하면 호출은 `wrong_credential_category`로
  거부됩니다. audit/history에는 credential metadata 스냅샷이 남지만
  secret/body/value 데이터는 절대 남지 않습니다.
- method는 `policy.allowed_methods`에 포함되어야 합니다.
- `request_path`는 `policy.allowed_request_path_prefixes`와 일치해야 합니다. 실제 호출 경로는 credential에 저장된 숨겨진 `base_path`와 `request_path`를 조합해 만듭니다.
- `policy.denied_query_keys`에 나열된 query key는 거부됩니다.
- 호출자 header는 `policy.allowed_request_headers`에 등록되지 않으면 거부됩니다.
- Auth, cookie, host, hop-by-hop, `X-Forwarded-*`, `Content-Type` request
  header는 항상 차단됩니다.
- 봉인된 secret header는 덮어쓸 수 없습니다.
- 대상 응답은 JSON이어야 하며, Content-Type이 JSON이 아니면 body를 읽기 전에 거부합니다.
- request body와 response body는 history나 audit에 저장되지 않습니다.
- target 전송 실패는 raw transport error를 저장하지 않고, 안전하게 분류된 경우
  `target_timeout`, `target_unreachable`, `target_private_network_blocked` 같은
  error kind와 짧은 safe message만 history에 저장합니다.
- history는 JSONPath 표현식을 projected value가 아니라 `projection_keys`로
  저장합니다.
- `truncated`는 top-level 필드로도 반환됩니다.
- `original_bytes`는 일반 응답에서는 compact 전 원본 body 크기이고, hard cap 초과 시에는 전체 크기 또는 확인된 최소 크기입니다.
- `jsonpath`는 표준 JSONPath 형식의 표현식을 사용하며 flat-keyed object를
  반환합니다.
- `jsonpath`는 공통 JSONPath 검증 규칙을 따릅니다. 표현식은 `$`로 시작해야
  하며, 최대 16개/각 512자까지 허용됩니다.
- recursive descent(`..`)는 허용되지 않습니다.

Truncation:

응답이 `max_bytes` 또는 hard read cap을 초과하면 `body=null`이 되고, `more`가 재시도 방법을
설명합니다. 응답에 따라 `more.options.preferred_next`는 `jsonpath` 또는
`narrow_jsonpath`가 될 수 있고, projection을 narrowing하는 데 도움이 되도록
`more.preview`에 path 메타데이터가 포함될 수 있습니다.

```json
{
  "status_code": 200,
  "body": null,
  "truncated": true,
  "original_bytes": 287000,
  "returned_bytes": 0,
  "latency_ms": 34,
  "more": {
    "truncated": true,
    "options": {
      "preferred_next": "jsonpath",
      "suggested_jsonpath": [
        "$.items[*].metadata.name",
        "$.items[*].status.phase"
      ],
      "suggested_max_bytes": 8192
    },
    "hints": [
      "retry with jsonpath=[\"$.items[*].metadata.name\",\"$.items[*].status.phase\"] using 1-3 paths from more.options.suggested_jsonpath",
      "last resort: retry with max_bytes=8192 to fit the full body"
    ]
  }
}
```

LLM 가이드:

- 먼저 `credential.list`를 호출해 policy를 확인하세요.
- 구조를 아는 API라면 곧바로 `jsonpath`를 사용하세요.
- 구조를 모르는 API라면 낮은 `max_bytes`로 시작한 뒤
  `more.options.preferred_next`를 따르세요.
- `max_bytes`를 올리기 전에 `suggested_jsonpath`/`more.preview.paths`를
  우선 사용하세요. `suggested_max_bytes`는 최후의 수단입니다.
- `suggested_max_bytes`는 대상 서버의 공백 포함 원본 응답 크기가 아니라
  opsgate가 반환할 compact JSON body 기준입니다.
- 일부 Kubernetes의 읽기성 API는 POST이며, 그래도 POST policy가 필요합니다.
- `origin=https://k8s.example.com`, `base_path=/cluster-a`, `request_path=/api/v1/pods`이면 실제 호출 URL은 `https://k8s.example.com/cluster-a/api/v1/pods`입니다. LLM은 `origin`과 `base_path`를 직접 보지 않습니다.

JSONPath 예시:

```json
{
  "alias": "prod-k8s",
  "purpose": "List running pod names",
  "method": "GET",
  "request_path": "/api/v1/pods",
  "jsonpath": [
    "$.items[?(@.status.phase == 'Running')].metadata.name"
  ]
}
```

Projection 출력:

```json
{
  "body": {
    "$.items[?(@.status.phase == 'Running')].metadata.name": [
      "api",
      "worker"
    ]
  }
}
```
