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
- policy 거부는 generic `policy_denied`로 뭉개지 않고
  `policy_method_not_allowed`, `policy_request_path_not_allowed`,
  `policy_query_key_denied`, `policy_request_header_blocked`,
  `policy_request_header_not_allowed` 중 하나로 분류됩니다.
- policy 거부 응답은 세부 kind와 복구 hint를 반환합니다. 정책 상세는
  `credential_list`를 다시 호출해 확인합니다. history/audit에는 세부 kind와
  safe message만 저장합니다.
- history는 JSONPath 표현식 또는 table의 `base`/`columns` 경로를 projected
  value가 아니라 `projection_keys`로 저장합니다. 둘 다 secret/URL이 없는 RFC 9535
  경로 문자열입니다.
- 출력 상태, truncation, JSONPath 검증은 공통
  [JSON 출력과 토큰 예산 스펙](../json-output.md)을 따릅니다.
- `original_bytes`는 일반 응답에서는 compact 전 원본 body 크기이고, source body read limit 초과 시에는 전체 크기 또는 확인된 최소 크기입니다.

큰 응답에서 `api_call`만의 차이:

- `source_body_too_large`가 가능하다. 이 경우 Opsgate가 target 응답 body를
  완전히 읽지 못한 것이므로 `max_bytes`나 `jsonpath`보다 target-native
  pagination, limit, cursor/continue, selector, filter, time range, 더 좁은
  `request_path`/`query`가 먼저다.
- source body read limit에 걸린 partial JSON은 파싱하지 않는다. 따라서
  `more.preview`, `suggested_jsonpath`, projected body를 만들지 않는다.
- `output_body_too_large`와 `projection_body_too_large`는 source JSON을 완전히
  읽은 뒤 output budget만 넘은 상태다. 공통 `next_action` 규칙은
  [JSON 출력과 토큰 예산 스펙](../json-output.md)을 따른다.

LLM 가이드:

- 먼저 `credential_list`를 호출해 policy를 확인하세요.
- 구조를 아는 API라면 곧바로 `jsonpath`를 사용하세요. 개수 질문에는 전체 배열을
  받지 말고 `.length()` 또는 `.count()`를 먼저 사용하세요.
- JSONPath projection은 matched-node list입니다. 여러 JSONPath 결과 배열의 같은
  index가 같은 source row라는 보장은 없습니다. optional field가 있는 row 정합성이
  필요하면 page/filter를 줄이고 `$.items[*]`처럼 row object 자체를 뽑거나,
  아래 `table`로 행마다 정렬된 object 배열을 받으세요.
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

## table

`jsonpath`가 경로마다 배열 하나(columnar)를 주는 것과 달리, `table`은 ragged
JSON을 **행마다 object 하나**인 배열로 재구성합니다 (SQL `JSON_TABLE`과 동일한 모델).
`base`가 행을 열거하고, `columns`의 각 항목은 컬럼 이름 → 각 행 기준 상대 경로입니다
(경로의 `$`는 해당 행 노드). `jsonpath`와 `table`은 상호 배타이며, 동시에
지정하면 거부됩니다.

규칙:

- `columns`가 비어 있으면 거부됩니다.
- column이 없는 행은 `null`이 됩니다.
- column이 여러 노드와 매칭되면 배열로 담깁니다(평탄화하지 않음).
- `base`/`columns` 경로는 `jsonpath`와 동일한 RFC 9535 안전 서브셋으로 검증됩니다.
  table은 평평한 컬럼만 지원하므로 `base`·`columns` 경로 모두 `.count()`/`.length()`
  집계는 쓸 수 없습니다(집계가 필요하면 `jsonpath` 모드를 사용하세요).
- 출력 `body_mode`는 `table_projection`입니다.
- output budget 초과 시 `next_action`은 `narrow_table_projection`이며, 복구는
  `columns` 줄이기 / `base` 좁히기 / `max_bytes` 올리기입니다.

입력:

```json
{
  "alias": "prod-k8s",
  "purpose": "List pod name and phase aligned per row",
  "method": "GET",
  "request_path": "/api/v1/pods",
  "table": {
    "base": "$.items[*]",
    "columns": {
      "name": "$.metadata.name",
      "phase": "$.status.phase"
    }
  }
}
```

출력:

```json
{
  "body_mode": "table_projection",
  "body_state": "returned",
  "body": [
    {"name": "vault-0", "phase": "Running"},
    {"name": "vault-1", "phase": null}
  ]
}
```
