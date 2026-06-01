# api.call boundary 모델

이 문서는 `api.call` 고유의 닫힌 boundary 모델을 정의합니다. `sql.query`는
다른 실행 모델을 가지므로 여기서 다루지 않습니다.

`api.call`의 목표는 LLM이 secret과 target URL 구성값(`origin`, `base_path`)을 보지 않은 채 등록된 HTTP
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
target URL leak
request/response body stored in history
query/header values stored in history
unbounded preview
target repeated pagination without preview cache
```

## Boundary chain

```text
input
  ↓
identity
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
request_path
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
request_path starts with /
request_path cannot contain .., //, ?, #
max_bytes range 256..1MiB
jsonpath max 16
jsonpath max length 512
headers max 16
header name max length 128
header name must be a valid HTTP token
header value max length 1024
header value CR/LF denied
Accept override must request JSON
query key count max 32
query key max length 128
query value max length 4096
query key/value CR/LF and NUL denied
```

입력이 비어 있으면 `method` 기본값은 `GET`, `max_bytes` 기본값은 4096입니다.

실패 시:

```text
target call 없음
secret decrypt 없음
safe denial/error만 기록
```


## 2. identity boundary

역할:

```text
유효한 인증 사용자인지 확인
```

불변조건:

```text
missing bearer token -> not_authenticated
invalid token -> not_authenticated
inactive user -> not_authenticated
active authenticated user -> pass
```

실패 시:

```text
credential lookup 없음
secret decrypt 없음
target call 없음
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
request_path prefix allow-list
denied query key
caller header allow-list
secret header override check
```

불변조건:

```text
credential not found -> denied
category != http -> denied
method not allowed -> denied
request_path not allowed -> denied
denied query key present -> denied
caller header not allow-listed -> denied
blocked header -> denied
caller header cannot override sealed secret header
```

통과 후 보장:

```text
LLM still has no target URL 구성값
LLM still has no secret
request is inside credential HTTP policy
```


## 4. target execution boundary

역할:

```text
정책을 통과한 요청을 실제 target API로 안전하게 실행
```

단계:

```text
sealed secret decrypt
target URL build from stored origin/base_path + validated request_path/query
default Accept: application/json
caller headers attach
Content-Type set only when content_type/body requires it
secret headers attach after caller headers
HTTP client selection
SSRF guarded dial
redirect blocked
Content-Type checked before body read
response body hard cap read
```

불변조건:

```text
origin/base_path only from credential row
redirect blocked
`allow_private_network=false`이면 private/link-local/loopback/cloud metadata 주소를 차단
call-time DNS/dial guard closes DNS rebinding window
response read cap is MaxMaxBytes
known oversized Content-Length is rejected without body read
unknown-size response stops after MaxMaxBytes+1 confirmed bytes
```

실패 시:

```text
safe public error
body 없음
audit/history outcome=error
transport 실패가 안전하게 분류된 경우 target_timeout/target_unreachable/target_private_network_blocked 같은 error_kind 기록
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
jsonpath projection returns flat-keyed object; `.length()`/`.count()` suffix may return small scalar counts
transport hard cap truncation is not parsed as JSON
top-level truncated mirrors the output truncation state
max_bytes truncation returns body=null
hard cap truncation returns body=null without parsing partial JSON
partial JSON never returned
```

가능한 출력:

```text
small valid JSON body
projected JSON body
body=null + more.truncated=true
error
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
request_path
query key names
caller request header names
jsonpath projection keys (`api_call_history.projection_keys`)
max_bytes
purpose
outcome
status_code
latency_ms
original_bytes (exact size or confirmed minimum when hard cap is hit)
returned_bytes
truncated
error_kind
safe error message
```

HTTP target 전송 실패는 raw `reqwest`/transport error를 저장하지 않습니다. 대신
opsgate가 안전하게 분류한 경우에만 `target_timeout`, `target_unreachable`,
`target_private_network_blocked` 같은 kind와 짧은 safe message를 저장합니다.

저장 금지:

```text
request body
response body
query values
header values
secret values
target URL
raw transport error with URL/secret risk
```


## 7. future cache boundary

현재 상태:

```text
bounded preview path catalog 구현됨
preview pagination 미구현
preview cache 미구현
```

0.1.0 규칙:

```text
preview pagination 없음
preview cache 없음
제한된 첫 preview page만 반환
```

future pagination 규칙:

```text
preview pagination은 반드시 `preview_id` cache를 사용해야 함
cache는 원본 response body를 저장하면 안 됨
cache는 path catalog와 statistics만 저장
cache는 TTL로 제한
cache는 owner/caller/request_id에 묶임
```


## 현재 구현 상태

현재 구현 기준:

```text
input boundary: validation test로 닫혀 있음
identity boundary: 닫혀 있음
credential/policy boundary: policy test로 닫혀 있음
target execution boundary: guard test로 닫혀 있음
response envelope boundary: JSON output test로 닫혀 있음
audit/history boundary: 단위/통합 테스트로 닫혀 있으며 live 스모크도 유효함
future cache boundary: 0.1.0 설계상 미구현
```

현재 0.1.0 범위 밖:

```text
preview cache
preview pagination
```
