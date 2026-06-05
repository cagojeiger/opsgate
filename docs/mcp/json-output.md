# JSON 출력과 토큰 예산 스펙

이 문서는 `api_call`이 target JSON 응답을, `sql_query`가 SQL 결과 JSON을
LLM에게 반환할 때의 공통 규칙을 정의합니다.

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
`api_call`은 `body`에 JSON 값을 그대로 반환합니다.

```json
{
  "status_code": 200,
  "body_mode": "raw_json",
  "body_state": "returned",
  "body": {
    "kind": "PodList",
    "items": []
  },
  "truncated": false,
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

## 출력 상태 필드

`api_call`과 `sql_query`의 JSON body 계열 출력은 기존 `body`, `truncated`,
`more`를 유지하면서 다음 상태 필드를 함께 반환합니다.

```text
body_mode      body의 JSON shape를 표시한다.
body_state     body가 반환됐는지 생략됐는지 표시한다.
omit_reason    body_state=omitted일 때 왜 빠졌는지 표시한다.
```

`body_state=omitted`이면 실제 `body`는 `null`입니다. 이때 `body_mode`는
`null`의 타입이 아니라, 크기 제한 전에 반환하려던 JSON shape를 표시합니다.

`body_mode`:

```text
raw_json              api_call target의 원본 JSON
columnar_json         sql_query rows를 컬럼별 배열로 전치한 JSON
jsonpath_projection   JSONPath projection 결과
```

`body_state`:

```text
returned
omitted
```

`omit_reason`:

```text
output_body_too_large       projection 없이 만든 JSON body가 max_bytes를 초과
projection_body_too_large   JSONPath projection 결과도 max_bytes를 초과
source_body_too_large       target 응답 body가 read limit을 초과해 완전 JSON을 읽지 못함
```

출력 결정은 두 단계로 나눕니다.

```text
1. Source Read
   Opsgate가 target/source body를 완전히 읽었는가?

2. Output Budget
   읽은 JSON 또는 JSONPath projection 결과가 max_bytes 안에 들어가는가?
```

따라서 `body=null`의 의미는 `omit_reason`으로 구분해야 합니다.

```text
source_body_too_large
  Opsgate가 source body를 완전히 읽지 못했다. partial JSON은 파싱하지 않는다.

output_body_too_large
  Opsgate는 source JSON을 완전히 읽었다. 다만 raw_json/columnar_json output이 max_bytes를 넘었다.

projection_body_too_large
  Opsgate는 source JSON을 완전히 읽고 JSONPath projection도 수행했다. 다만 projection output이 max_bytes를 넘었다.
```

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
  "body_mode": "jsonpath_projection",
  "body_state": "returned",
  "body": {
    "$.items[*].metadata.name": ["api", "worker"],
    "$.items[*].status.phase": ["Running", "Pending"]
  }
}
```

`jsonpath_projection`은 각 표현식의 matched-node list를 flat-keyed object로
반환합니다. 여러 JSONPath 결과 배열의 같은 index가 같은 source row라는 보장은
없습니다. optional field가 있는 API row 정합성이 필요하면 target-native
pagination/filter로 page를 줄인 뒤 `$.items[*]`처럼 row object 자체를
projection하세요. SQL `columnar_json`은 별도 로직으로 missing column을 `null`로
padding하므로 이 API JSONPath projection 경고와 다릅니다.

## JSONPath 검증 규칙

`api_call`과 `sql_query`는 같은 JSONPath 검증을 사용합니다. 기본은
`serde_json_path` parser가 받아들이는 RFC 9535 호환 JSONPath filter이며,
정규식 필터는 RFC 9535식 `search(value, pattern)`/`match(value, pattern)`
함수를 사용합니다. 토큰 절감을 위해 끝에 붙이는 작은 집계 suffix
`.length()`/`.count()`도 지원합니다.

허용 조건:

```text
표현식 개수 최대 16
표현식 길이 최대 512
표현식은 $ 로 시작
recursive descent(`..`) 금지
parser가 유효한 JSONPath로 인정해야 함
끝에 `.length()`/`.length` 또는 `.count()`/`.count` 집계 suffix 허용
```

자주 쓰는 예시는 다음과 같습니다.

```text
$
$.field
$.items[*]
$.items[0]
$.items[0:10]
$.items['name','namespace']
$.items[?(@.status.phase == 'Running')]
$.items[?search(@.metadata.name, 'api|worker')].metadata.name
$.items[?match(@.metadata.name, 'api-[0-9]+')].metadata.name
$.items.length()                    # 배열/문자열/object 길이
$.items[*].metadata.name.count()    # 매칭 node 개수
```

`.length()`는 매칭된 값이 하나면 배열/문자열/object 길이를 숫자로 반환하고, 여러 값이면 각 값의 길이 배열을 반환합니다. `.count()`는 base JSONPath가 매칭한 node 개수를 숫자로 반환합니다. 매칭이 없으면 일반 selection과 `.length()`는 `[]`, `.count()`는 `0`을 반환합니다.

정규식 필터는 RFC 9535의 `search(value, pattern)`/`match(value, pattern)`
함수 형식을 사용합니다. `search`는 부분 검색, `match`는 전체 문자열 매칭입니다.

SQL의 column-oriented body에서 `$.column.count()`는 보통 배열 node 1개를 세므로 행 수가 아닙니다. SQL 행 수는 응답의 `row_count` 또는 `$.column.length()`를 사용합니다.
의도는 무제한 recursive traversal을 막으면서도 LLM이 필요한 값이나 개수만 작게
가져올 수 있게 하는 것입니다.

## 큰 응답 처리

`body_state=omitted`이면 공통 envelope은 다음 규칙을 따릅니다.

```text
body=null
truncated=true
returned_bytes=0
partial JSON 문자열 반환 금지
response body audit/history 저장 금지
more.options.next_action으로 다음 호출 축소 방향 제공
```

생략/sidecar 상태와 `next_action`의 의미:

```text
source_body_too_large      -> narrow_request
  source body를 완전히 못 읽었다. max_bytes/jsonpath보다 request path/query/body,
  target-native pagination/filter/limit/selector/time range를 먼저 줄인다.

output_body_too_large      -> add_jsonpath
  source JSON은 읽혔지만 raw_json/columnar_json output이 max_bytes를 넘었다.
  suggested_jsonpath 또는 more.preview.paths에서 1-3개를 골라 output을 좁힌다.

projection_body_too_large  -> narrow_jsonpath
  source JSON은 읽혔고 JSONPath도 수행했지만 projection output이 아직 크다.
  expression 개수, slice 범위, filter 조건을 더 줄인다.

row_limit                  -> adjust_max_rows
  SQL row limit에 걸렸다. max_rows, WHERE, aggregate, keyset pagination을 조정한다.
```

`suggested_max_bytes`는 compact JSON body 기준이며 마지막 수단입니다. source body
read limit 초과에는 도움이 되지 않습니다. source body read limit에 걸린 경우
`more.preview`와 `suggested_jsonpath`는 만들지 않습니다.

최소 예시:

```json
{
  "body_state": "omitted",
  "omit_reason": "output_body_too_large",
  "body": null,
  "truncated": true,
  "more": {
    "truncated": true,
    "options": {
      "next_action": "add_jsonpath",
      "suggested_jsonpath": [
        "$.items[*].metadata.name",
        "$.items[*].status.phase"
      ],
      "suggested_max_bytes": 8192
    }
  }
}
```

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

이유: `api_call`은 target 실행 도구입니다. 캐시 없이 preview page를 더
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

## Preview 사용 규칙

`more.preview`는 `add_jsonpath`를 돕는 첫 화면 힌트입니다. paging 인터페이스가
아니므로 preview가 잘렸다면 preview를 더 보려 하지 말고 더 좁은 JSONPath로
재호출합니다.

```text
1. present_sampled가 높은 scalar path부터 사용한다.
2. 중첩 배열 path는 꼭 필요할 때만 사용한다.
3. full response가 작다는 확신이 있고 policy가 허용할 때만 max_bytes를 올린다.
```

## 현재 구현 상태

구현됨:

```text
JSON-only response envelope
max_bytes truncation 시 body=null
source body read limit 보호
jsonpath 입력
JSONPath safe subset 검증
jsonpath `.length()`/`.count()` 집계 suffix
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
