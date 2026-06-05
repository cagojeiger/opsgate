# `api_call`

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
  "body_mode": "jsonpath_projection",
  "body_state": "returned",
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
- `body_mode`는 `raw_json` 또는 `jsonpath_projection`입니다.
- `body_state`는 `returned` 또는 `omitted`입니다.
- `omit_reason`은 `body_state=omitted`일 때 `output_body_too_large`,
  `projection_body_too_large`, `source_body_too_large` 중 하나입니다.
- `truncated`는 top-level 필드로도 반환됩니다.
- `original_bytes`는 일반 응답에서는 compact 전 원본 body 크기이고, source body read limit 초과 시에는 전체 크기 또는 확인된 최소 크기입니다.
- `jsonpath`는 JSONPath 표현식을 사용하며 flat-keyed object를 반환합니다.
  `length()`는 배열/문자열/object 길이, `count()`는 매칭 node 개수를 반환합니다.
- `jsonpath`는 공통 JSONPath 검증 규칙을 따릅니다. 표현식은 `$`로 시작해야
  하며, 최대 16개/각 512자까지 허용됩니다.
- recursive descent(`..`)는 허용되지 않습니다.
- 예: pod 수만 필요하면 `$.items.length()`, 매칭된 이름 개수만 필요하면
  `$.items[*].metadata.name.count()`를 사용합니다.

Truncation:

응답이 `body=null`이면 `omit_reason`을 먼저 봅니다.

- `source_body_too_large`: Opsgate가 target 응답 body를 완전히 읽지 못했습니다.
  `max_bytes`나 `jsonpath`보다 target-native pagination, limit, cursor/continue,
  selector, filter, time range, 더 좁은 `request_path`/`query`가 먼저입니다.
- `output_body_too_large`: Opsgate는 source JSON을 완전히 읽었습니다. 다만 tool
  output budget을 넘었으므로 `suggested_jsonpath` 또는 `more.preview.paths`로
  output만 좁힙니다.
- `projection_body_too_large`: Opsgate는 source JSON을 완전히 읽고 JSONPath도
  적용했습니다. JSONPath expression 수, slice 범위, filter 조건을 더 줄입니다.

`more.preview`는 source JSON을 완전히 읽었지만 output이 큰 경우에만 붙을 수
있습니다. source body read limit에 걸린 partial JSON은 파싱하지 않으므로 preview를
만들지 않습니다.

```json
{
  "status_code": 200,
  "body_mode": "raw_json",
  "body_state": "omitted",
  "omit_reason": "output_body_too_large",
  "body": null,
  "truncated": true,
  "original_bytes": 287000,
  "latency_ms": 34,
  "more": {
    "truncated": true,
    "options": {
      "next_action": "add_jsonpath",
      "suggested_jsonpath": [
        "$.items[*].metadata.name",
        "$.items[*].status.phase"
      ],
      "suggested_max_bytes": 8192
    },
    "hints": [
      "Opsgate read the full JSON, but the tool output budget is too small; retry with jsonpath using 1-3 paths from suggested_jsonpath or preview.paths"
    ]
  }
}
```

LLM 가이드:

- 먼저 `credential_list`를 호출해 policy를 확인하세요.
- 구조를 아는 API라면 곧바로 `jsonpath`를 사용하세요. 개수 질문에는 전체 배열을
  받지 말고 `.length()` 또는 `.count()`를 먼저 사용하세요.
- 구조를 모르는 API라면 낮은 `max_bytes`로 시작한 뒤
  `more.options.next_action`을 따르세요.
- `next_action=add_jsonpath`이면 source는 이미 읽혔으므로 `suggested_jsonpath`/
  `more.preview.paths`를 우선 사용하세요. `suggested_max_bytes`는 최후의
  수단입니다.
- `next_action=narrow_request`이면 Opsgate가 source를 완전히 읽지 못한 것입니다.
  target API의 pagination/filter/selector/time range로 request 자체를 줄이세요.
- `suggested_max_bytes`는 대상 서버의 공백 포함 원본 응답 크기가 아니라
  opsgate가 반환할 compact JSON body 기준입니다.
- JSONPath projection은 matched-node list입니다. 여러 JSONPath 결과 배열의 같은
  index가 같은 source row라는 보장은 없습니다. optional field가 있는 row 정합성이
  필요하면 page/filter를 줄이고 `$.items[*]`처럼 row object 자체를 projection하세요.
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

정규식 기반 부분 검색은 RFC 9535식 `search(value, pattern)` 함수를 사용합니다. 전체 문자열 매칭은 `match(value, pattern)`를 사용합니다.

```json
{
  "alias": "prod-k8s",
  "purpose": "List API pod names",
  "method": "GET",
  "request_path": "/api/v1/pods",
  "jsonpath": [
    "$.items[?search(@.metadata.name, 'api')].metadata.name"
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
