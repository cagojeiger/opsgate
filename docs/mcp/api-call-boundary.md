# api.call boundary model

이 문서는 `api.call` 고유의 닫힌 boundary 모델을 정의합니다. `sql.query`는
다른 실행 모델을 가지므로 여기서 다루지 않습니다.

`api.call`의 목표는 LLM이 secret과 endpoint를 보지 않은 채 등록된 HTTP
credential을 안전하게 사용하는 것입니다.

닫힌 종료 상태는 네 가지뿐이어야 합니다.

```text
1. denied with safe reason
2. error with safe kind
3. body=null + hints
4. small valid JSON
```

금지 상태:

```text
partial JSON
huge body
secret leak
endpoint leak
request/response body stored in history
query/header values stored in history
unbounded preview
target repeated pagination without preview cache
```

## Boundary chain

```text
input
  ↓
identity / role
  ↓
credential / policy
  ↓
target execution
  ↓
response envelope
  ↓
audit / history
```

Preview는 `response envelope` 안에서 생성되는 bounded helper입니다. 원본
body를 저장하는 cache boundary는 아직 구현하지 않습니다. 0.1.0에서는 preview
pagination도 제공하지 않습니다.

## 1. input boundary

역할:

```text
LLM이 준 입력이 api.call 표면에 들어와도 되는 모양인지 확인
```

대상 입력:

```text
alias
purpose
method
path
query
headers
body
content_type
max_bytes
jsonpath
```

불변조건:

```text
alias required
purpose required
purpose length 8-512
purpose CR/LF denied
method in GET/POST/PUT/PATCH/DELETE
GET body denied
path starts with /
path cannot contain .., //, ?, #
max_bytes range 256..1MiB
jsonpath max 16
jsonpath max length 512
headers max 16
header name max length 128
header name must be a valid HTTP token
header value max length 1024
header value CR/LF denied
Accept override must request JSON
```

입력이 비어 있으면 `method` 기본값은 `GET`, `max_bytes` 기본값은 4096입니다.

실패 시:

```text
target call 없음
secret decrypt 없음
safe denial/error만 기록
```

P0 TC:

```text
TestValidateInputRequiresPurpose
TestValidateInputRejectsPurposeWithCRLF
TestValidateInputRejectsTraversal
TestValidateInputRejectsTooManyJSONPathExpressions
TestValidateInputRejectsUnsupportedJSONPathFragment
TestValidateInputRejectsNonJSONAccept
```

## 2. identity / role boundary

역할:

```text
누가 api.call을 실행할 수 있는지 확인
```

불변조건:

```text
nil caller -> not_authenticated
nil user -> not_authenticated
inactive user -> not_authenticated
viewer -> viewer_cannot_call
operator/admin -> pass
```

실패 시:

```text
credential lookup 없음
secret decrypt 없음
target call 없음
```

P0 TC:

```text
api.call rejects unauthenticated caller before credential lookup
api.call rejects viewer before credential lookup
```

## 3. credential / policy boundary

역할:

```text
이 alias로 이 HTTP 요청이 허용되는지 확인
```

단계:

```text
credential lookup by owner_user_id + alias
category=http 확인
policy parse
method allow-list
path prefix allow-list
denied query key
caller header allow-list
secret header override check
```

불변조건:

```text
credential not found -> denied
category != http -> denied
method not allowed -> denied
path not allowed -> denied
denied query key present -> denied
caller header not allow-listed -> denied
blocked header -> denied
caller header cannot override sealed secret header
```

통과 후 보장:

```text
LLM still has no endpoint
LLM still has no secret
request is inside credential HTTP policy
```

P0 TC:

```text
api.call rejects wrong category
api.call wrong-category denial keeps credential metadata snapshot
api.call rejects denied query key
api.call rejects disallowed caller header
api.call rejects secret header override
api.call rejects method/path outside policy
```

## 4. target execution boundary

역할:

```text
정책을 통과한 요청을 실제 target API로 안전하게 실행
```

단계:

```text
sealed secret decrypt
target URL build from stored endpoint + validated path/query
default Accept: application/json
caller headers attach
Content-Type set only through content_type/body path
secret headers attach after caller headers
HTTP client selection
SSRF guarded dial
redirect blocked
response body hard cap read
```

불변조건:

```text
endpoint only from credential row
redirect blocked
allow_private_network=false blocks private/link-local/loopback/cloud metadata
call-time DNS/dial guard closes DNS rebinding window
response read cap is MaxMaxBytes
```

실패 시:

```text
safe public error
body 없음
audit/history outcome=error
```

P0 TC:

```text
api.call blocks redirect
api.call blocks private call-time target when allow_private_network=false
api.call reads at most hard cap before envelope
```

## 5. response envelope boundary

역할:

```text
target 응답을 LLM이 안전하게 소비할 수 있는 JSON envelope으로 변환
```

불변조건:

```text
Content-Type must indicate JSON
JSON parse must succeed
multiple top-level JSON values denied
top-level scalar JSON allowed
UseNumber preserves large JSON numbers
jsonpath projection returns flat-keyed object
transport hard cap truncation is not parsed as JSON
max_bytes truncation returns body=null
partial JSON never returned
```

가능한 출력:

```text
small valid JSON body
projected JSON body
body=null + more.truncated=true
error
```

P0 TC:

```text
TestBuildEnvelopeInlinesJSONBody
TestBuildEnvelopeAppliesJSONPath
TestBuildEnvelopeAllowsTopLevelScalarJSON
TestBuildEnvelopeRejectsNonJSON
TestBuildEnvelopeRejectsBrokenJSON
TestBuildEnvelopeRejectsMultipleTopLevelJSONValues
TestBuildEnvelopeTruncatedReturnsNullBody
TestBuildEnvelopeTransportTruncatedReturnsHintsWithoutParsing
```

## 6. audit / history boundary

역할:

```text
사후 조사와 운영 분석에 필요한 사실만 저장
```

저장 가능:

```text
actor / owner
channel
request_id
credential id/alias/category/provider/env snapshot
method
path
query key names
caller request header names
jsonpath projection keys (`api_call_history.projection_keys`)
max_bytes
purpose
outcome
status_code
latency_ms
original_bytes
returned_bytes
truncated
error_kind
safe error message
```

저장 금지:

```text
request body
response body
query values
header values
secret values
endpoint URL
raw transport error with URL/secret risk
```

P0 TC:

```text
api.call history stores projection keys but not body
api.call history stores query/header keys but not values
api.call audit stores purpose/method/path/outcome but not body
api.call truncation history has truncated=true and no response body
api.call wrong-category denial stores credential snapshot but no secret/body/value
```

## 7. future cache boundary

현재 상태:

```text
bounded preview path catalog implemented
preview pagination not implemented
preview cache not implemented
```

0.1.0 규칙:

```text
no preview pagination
no preview cache
return only bounded first preview page
```

future pagination 규칙:

```text
preview pagination MUST use preview_id cache
cache MUST NOT store original response body
cache stores only path catalog + statistics
cache is TTL-bound
cache is bound to owner/caller/request_id
```

P2 TC:

```text
preview catalog respects max_preview_bytes
preview catalog respects max_preview_paths
preview cache read checks caller binding
preview cache never stores raw response body
```

## Current closure assessment

현재 구현 기준:

```text
input boundary: mostly closed
identity/role boundary: closed
credential/policy boundary: mostly closed
target execution boundary: mostly closed
response envelope boundary: mostly closed
audit/history boundary: mostly closed, live MCP smoke remains valuable
future cache boundary: not implemented by design for 0.1.0
```

0.1.0에서 닫아야 할 우선순위:

```text
P0:
  live MCP smoke revalidation after docs sync
  api.call target-not-called tests for bad jsonpath/input
  MCP schema accepts all JSON body scalar/object/array/null cases

P1:
  audit/history no-body/no-value regression tests for new tool paths
  response preview quality tuning

P2:
  preview cache/pagination
```
