# `api.call`

Surface:

```text
/mcp
```

Purpose: `category=http` credential을 통해 등록된 HTTPS API를 호출합니다.

응답 truncation, JSONPath projection, 토큰 예산 규칙은
[JSON 출력과 토큰 예산 스펙](../json-output.md)에 정의합니다.

Input:

```json
{
  "alias": "prod-k8s",
  "purpose": "Check pod phases before summarizing cluster health",
  "method": "GET",
  "path": "/api/v1/pods",
  "query": {"limit": "100"},
  "headers": {"Accept": "application/json"},
  "body": null,
  "content_type": "",
  "jsonpath": ["$.items[*].metadata.name", "$.items[*].status.phase"],
  "max_bytes": 4096
}
```

Required:

- `alias`
- `purpose`
- `path`

Constraints:

- `purpose`는 8~512자이며 CR/LF를 포함할 수 없습니다.
- `max_bytes` 허용 범위는 256~1048576입니다.

Defaults:

- `method=GET`
- `max_bytes=4096`
- policy가 override를 허용하지 않는 한 JSON `Accept`가 자동으로 전송됩니다.
- non-GET JSON body는 기본적으로 `Content-Type: application/json`을 사용합니다.

Output:

```json
{
  "status_code": 200,
  "headers": {"Content-Type": "application/json"},
  "body": {
    "items.metadata.name": ["api", "worker"],
    "items.status.phase": ["Running", "Running"]
  },
  "original_bytes": 287000,
  "returned_bytes": 420,
  "latency_ms": 34
}
```

Rules:

- credential은 `category=http`여야 합니다.
- alias는 존재하지만 다른 category에 속하면 호출은 `wrong_credential_category`로
  거부됩니다. audit/history에는 credential metadata 스냅샷이 남지만
  secret/body/value 데이터는 절대 남지 않습니다.
- method는 `policy.allowed_methods`에 포함되어야 합니다.
- path는 `policy.allowed_path_prefixes`와 일치해야 합니다.
- `policy.denied_query_keys`에 나열된 query key는 거부됩니다.
- 호출자 header는 `policy.allowed_request_headers`에 등록되지 않으면 거부됩니다.
- Auth, cookie, host, hop-by-hop, `X-Forwarded-*`, `Content-Type` request
  header는 항상 차단됩니다.
- 봉인된 secret header는 덮어쓸 수 없습니다.
- 대상 응답은 JSON이어야 합니다.
- request body와 response body는 history나 audit에 저장되지 않습니다.
- history는 JSONPath 표현식을 projected value가 아니라 `projection_keys`로
  저장합니다.
- `jsonpath`는 표준 JSONPath 형식의 표현식을 사용하며 flat-keyed object를
  반환합니다.
- `jsonpath`는 api.call safe subset(root, child, index, slice, wildcard,
  union, filter 표현식)으로 허용됩니다.
- recursive descent와 라이브러리 고유 script 확장은 초기 safe subset에
  포함되지 않습니다.

Truncation:

응답이 `max_bytes`를 초과하면 `body=null`이 되고, `more`가 재시도 방법을
설명합니다. 응답에 따라 `more.options.preferred_next`는 `jsonpath` 또는
`narrow_jsonpath`가 될 수 있고, projection을 narrowing하는 데 도움이 되도록
`more.preview`에 path 메타데이터가 포함될 수 있습니다.

```json
{
  "status_code": 200,
  "body": null,
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

LLM guidance:

- 먼저 `credential.list`를 호출해 policy를 확인하세요.
- 구조를 아는 API라면 곧바로 `jsonpath`를 사용하세요.
- 구조를 모르는 API라면 낮은 `max_bytes`로 시작한 뒤
  `more.options.preferred_next`를 따르세요.
- `max_bytes`를 올리기 전에 `suggested_jsonpath`/`more.preview.paths`를
  우선 사용하세요. `suggested_max_bytes`는 최후의 수단입니다.
- `suggested_max_bytes`는 대상 서버의 공백 포함 원본 응답 크기가 아니라
  opsgate가 반환할 compact JSON body 기준입니다.
- 일부 Kubernetes의 읽기성 API는 POST이며, 그래도 POST policy가 필요합니다.

JSONPath example:

```json
{
  "alias": "prod-k8s",
  "purpose": "List running pod names",
  "method": "GET",
  "path": "/api/v1/pods",
  "jsonpath": [
    "$.items[?(@.status.phase == 'Running')].metadata.name"
  ]
}
```

Projection output:

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
