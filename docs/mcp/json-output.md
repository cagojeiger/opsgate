# JSON 출력과 토큰 예산 스펙

이 문서는 `api.call`이 target JSON 응답을 LLM에게 반환할 때의 규칙을
정의합니다.

목표는 target 응답 전체를 그대로 보여주는 것이 아닙니다. 목표는 LLM이
다음 호출을 정확히 좁힐 수 있을 만큼의 구조화된 정보를, 토큰 예산 안에서
안전하게 제공하는 것입니다.

## 원칙

```text
1. 깨진 JSON을 반환하지 않는다.
2. JSON 중간을 임의로 잘라서 반환하지 않는다.
3. 자체 path 문법을 키우기보다 표준 JSONPath projection을 우선한다.
4. preview도 반드시 크기 제한을 둔다.
5. response body는 audit/history에 저장하지 않는다.
```

## 정상 응답

target 응답이 유효한 JSON이고 compact JSON 크기가 `max_bytes` 안에 들어오면
`api.call`은 `body`에 JSON 값을 그대로 반환합니다.

```json
{
  "status_code": 200,
  "body": {
    "kind": "PodList",
    "items": []
  },
  "original_bytes": 1840,
  "returned_bytes": 31,
  "latency_ms": 18
}
```

`body`는 모든 유효한 JSON 값을 담을 수 있습니다.

```text
object
array
string
number
boolean
null
```

JSON number는 `UseNumber`로 decode합니다. 큰 숫자 ID가 `float64`로 강제
변환되면서 정밀도가 깨지는 것을 피하기 위한 선택입니다.

## Projection

큰 target JSON은 `jsonpath`로 필요한 값만 뽑는 것이 기본 전략입니다.

입력:

```json
{
  "jsonpath": [
    "$.items[*].metadata.name",
    "$.items[*].status.phase"
  ]
}
```

출력:

```json
{
  "body": {
    "$.items[*].metadata.name": ["api", "worker"],
    "$.items[*].status.phase": ["Running", "Pending"]
  }
}
```

## JSONPath safe subset

`api.call`은 JSONPath 전체를 무제한으로 열지 않고, 설명 가능하고 제한된
safe subset만 허용합니다.

허용:

```text
$
$.field
$.items[*]
$.items[0]
$.items[0:10]
$.items['name','namespace']
$.items[?(@.status.phase == 'Running')]
```

초기 버전에서 제외:

```text
$..recursive
script 확장
safe subset 밖의 라이브러리 고유 연산자
```

의도는 표준 문법으로 좁히되, 무제한 traversal이나 구현체 특화 동작을
초기 표면에 열지 않는 것입니다.

## 큰 응답 처리 규칙

target JSON이 호출자의 `max_bytes`보다 크면 `api.call`은 전체 body를
반환하지 않습니다.

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
      "increase max_bytes only after projection if the projected output is still too large and policy allows it",
      "last resort: retry with max_bytes=8192 to fit the full body"
    ]
  }
}
```

규칙:

```text
body=null
more.truncated=true
partial JSON 문자열 반환 금지
response body audit/history 저장 금지
다음 호출을 좁힐 수 있는 structured option과 hint 제공
```

target 응답이 hard read cap을 넘는 경우에도, 불완전한 JSON prefix를
파싱하려고 하지 않습니다. 대신 truncated envelope을 반환합니다.

## 점진적 호출 프로토콜

`api.call`은 큰 JSON을 한 번에 많이 보여주는 도구가 아닙니다. LLM이 작은
호출에서 시작해서 필요한 정보만 점진적으로 가져오도록 설계합니다.

`more.options.preferred_next`는 다음 호출의 우선 행동입니다.

```text
jsonpath          projection 없이 큰 응답을 받았으니 JSONPath로 좁힌다.
narrow_jsonpath   이미 JSONPath를 썼지만 결과가 아직 크니 표현식을 더 좁힌다.
```

규칙:

```text
1. body=null이면 max_bytes부터 올리지 않는다.
2. preferred_next=jsonpath이면 suggested_jsonpath에서 1-3개만 골라 재호출한다.
3. suggested_jsonpath가 없으면 more.preview.paths에서 scalar path를 고른다.
4. preferred_next=narrow_jsonpath이면 expression 개수, slice 범위, filter 조건을 줄인다.
5. max_bytes 증가는 projection 결과도 필요한데 여전히 큰 경우의 마지막 수단이다.
6. hard read cap 초과 시 max_bytes 증가는 도움이 되지 않는다.
```

예시:

```json
{
  "more": {
    "truncated": true,
    "options": {
      "preferred_next": "jsonpath",
      "suggested_jsonpath": [
        "$.items[*].metadata.name",
        "$.items[*].status.phase"
      ],
      "suggested_max_bytes": 8192
    }
  }
}
```

위 경우 다음 호출은 이렇게 해야 합니다.

```json
{
  "jsonpath": [
    "$.items[*].metadata.name",
    "$.items[*].status.phase"
  ],
  "max_bytes": 4096
}
```

`suggested_max_bytes`가 있어도 먼저 사용하지 않습니다. 이 값은 compact JSON
body를 정말 봐야 할 때의 last resort입니다. upstream 응답의 공백까지 포함한
raw byte 크기가 아니라, opsgate가 실제 반환할 compact/projection body 크기를
기준으로 계산합니다.

## Preview path catalog

응답이 유효한 JSON이지만 `max_bytes`보다 큰 경우, opsgate는
`more.preview`에 제한된 preview catalog를 제공합니다.

preview는 전체 schema가 아닙니다. LLM이 다음 `jsonpath`를 고를 수 있게
돕는 작은 JSONPath 후보 목록과 필드 통계입니다.

추천 shape:

```json
{
  "preview": {
    "path_count": 240,
    "returned_paths": 20,
    "truncated": true,
    "paths": [
      {
        "path": "$.items[*].metadata.name",
        "type": "string",
        "present_sampled": 120,
        "nulls_sampled": 0
      },
      {
        "path": "$.items[*].status.phase",
        "type": "string",
        "present_sampled": 118,
        "nulls_sampled": 2
      },
      {
        "path": "$.items[*].status.containerStatuses",
        "type": "array",
        "present_sampled": 120,
        "array_length_min_sampled": 1,
        "array_length_max_sampled": 4,
        "nested_expansion_stopped": true
      }
    ]
  }
}
```

필드 통계:

```text
path
type
present_sampled
nulls_sampled
array_length_min_sampled
array_length_max_sampled
nested_expansion_stopped
```

`present_sampled`는 배열 sampling이 들어간 경우 sample 기반 값입니다. 전체
구조를 모두 본 것이 아니라면 full count처럼 표현하면 안 됩니다.

## Preview 예산 제한

preview 자체도 반드시 제한합니다. 큰 JSON을 줄이기 위한 preview가 다시
큰 응답이 되면 안 됩니다.

추천 기본값:

```text
max_preview_bytes = 4096
max_preview_paths = 20
max_preview_depth = 5
max_array_sample = 10
max_nested_array_expansion = 1
examples = 기본 off
```

중첩 배열은 특히 위험합니다.

```text
items[*].containers[*].env[*]
```

이런 구조는 `n*m*k`로 커질 수 있습니다. preview sampler는 중첩 배열 확장을
일찍 멈추고 표시해야 합니다.

```json
{
  "path": "$.items[*].containers",
  "type": "array",
  "nested_expansion_stopped": true
}
```

## Pagination 결정

`0.1.0`에서는 preview pagination을 추가하지 않습니다.

이유: `api.call`은 target 실행 도구입니다. 캐시 없이 preview page를 더
보려면 같은 target API를 다시 호출해야 합니다. 캐시를 추가하면 TTL, 권한,
메모리 제한, response retention 정책이 따라옵니다.

`0.1.0` 규칙:

```text
첫 preview page만 제한적으로 반환
더 보고 싶으면 preview를 더 요청하지 말고 더 좁은 jsonpath로 재호출
```

나중에 고려할 수 있는 별도 도구:

```text
api.preview_read(preview_id, cursor, limit)
```

이 기능은 preview browsing이 실제로 자주 필요해질 때, 짧은 TTL의 preview
index cache와 함께 검토합니다.

## LLM 권장 동작

`body=null`이고 `more.truncated=true`이면:

```text
1. max_bytes를 올리기보다 jsonpath를 우선 사용한다.
2. preview가 있으면 present_sampled가 높은 path부터 사용한다.
3. 중첩 배열 path는 꼭 필요할 때만 사용한다.
4. preview가 잘렸다면 preview를 더 보려 하지 말고 더 좁은 jsonpath를 만든다.
5. full response가 작다는 확신이 있고 policy가 허용할 때만 max_bytes를 올린다.
```

## 현재 구현 상태

구현됨:

```text
JSON-only response envelope
max_bytes truncation 시 body=null
hard read cap 보호
jsonpath 입력
JSONPath safe subset 검증
top-level scalar JSON 출력 지원
UseNumber decode
more.preview path catalog
field count sampling
nested array expansion marker
preview byte/path/depth/sample budget enforcement
```

아직 미구현:

```text
preview pagination
preview_id cache
```
