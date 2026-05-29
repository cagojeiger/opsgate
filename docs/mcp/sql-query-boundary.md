# sql.query boundary model

이 문서는 `sql.query` 고유의 닫힌 boundary 모델을 정의합니다. `api.call`은
HTTP/JSON 응답을 다루지만, `sql.query`는 Postgres 데이터베이스에 대해
읽기 전용 SQL을 실행하고 결과 행렬을 작은 JSON envelope으로 변환합니다.

`sql.query`의 목표는 LLM이 DB password와 endpoint를 보지 않은 채 등록된
Postgres credential을 안전하게 사용하고, 필요한 만큼만 결과를 가져오게
하는 것입니다.

테이블/컬럼 구조를 모를 때는 먼저 `sql.schema`를 사용합니다. `sql.schema`는
row 값을 반환하지 않고 고정 JSON 구조만 반환하며, `sql.query`와 같은 SQL JSON
출력 공통 유틸리티를 공유합니다.

닫힌 종료 상태는 네 가지뿐이어야 합니다.

```text
1. denied with safe reason
2. error with safe kind
3. truncated output + more hints
4. small JSON result
```

금지 상태:

```text
secret leak
endpoint leak
query text stored in history
SQL params values stored in history
result values stored in history
write/lock/side-effect query execution
unbounded result set
Postgres internal value rendering leak
```

## Boundary chain

```text
input
  ↓
identity / role
  ↓
credential / policy
  ↓
SQL AST policy
  ↓
target execution
  ↓
output shape / budget
  ↓
audit / history
```

## 1. input boundary

역할:

```text
LLM이 준 SQL 요청이 sql.query 표면에 들어와도 되는 모양인지 확인
```

대상 입력:

```text
alias
purpose
query
params
shape
max_rows
max_bytes
timeout_ms
```

불변조건:

```text
alias required
purpose required
purpose length 8-512
purpose CR/LF denied
query required
query length 1-16000
query NUL denied
params max count 64
shape in rows/columns/values
max_rows range 1..1000
max_bytes range 1024..1MiB
timeout_ms range 1..30000
```

이 단계의 한도는 credential policy와 무관한 절대 상한입니다. policy가 더
낮은 cap을 지정했는지는 별도의 credential / policy boundary에서 검사합니다.
입력이 비어 있으면 적용되는 기본값은 다음과 같습니다.

```text
shape default rows
max_rows default 100
max_bytes default 64KiB
timeout_ms default 3000
```

실패 시:

```text
DB connection 없음
secret decrypt 없음
safe denial/error만 기록
```

## 2. identity / role boundary

역할:

```text
누가 sql.query를 실행할 수 있는지 확인
```

불변조건:

```text
nil caller -> not_authenticated
nil user -> not_authenticated
inactive user -> not_authenticated
viewer -> viewer_cannot_query
operator/admin -> pass
```

실패 시:

```text
credential lookup 없음
secret decrypt 없음
DB connection 없음
```

## 3. credential / policy boundary

역할:

```text
이 alias가 SQL credential인지, 그리고 요청 예산이 policy 안에 있는지 확인
```

불변조건:

```text
credential not found -> denied
category != sql -> denied
provider != postgres -> denied
allow_explain_analyze=true without allow_explain -> denied
request max_rows > policy max_rows (when policy cap > 0) -> denied
request max_bytes > policy max_bytes (when policy cap > 0) -> denied
request timeout_ms > policy timeout_ms (when policy cap > 0) -> denied
```

policy의 `max_rows`/`max_bytes`/`timeout_ms`가 0이면 cap이 없는 것으로 보고,
입력 boundary의 절대 상한만 적용합니다.

통과 후 보장:

```text
LLM still has no DB endpoint
LLM still has no password
request budget is inside SQL policy
```

중요한 설계:

```text
opsgate has no general schema whitelist policy.
The database endpoint selects the database boundary.
The DB role grants decide which tables are reachable.
```

단, Postgres metadata 영역은 별도 정책 축입니다.

```text
pg_catalog / information_schema access requires allow_metadata=true.
This is metadata gating, not a general schema whitelist.
```

## 4. SQL AST policy boundary

역할:

```text
쿼리를 실행하기 전에 AST로 위험한 SQL 모양을 거절
```

불변조건:

```text
single statement only
SELECT or WITH only
writes rejected
locking clauses rejected
built-in blocked functions rejected
denied_functions rejected
SQL value functions in denied_functions rejected
EXPLAIN requires allow_explain=true
EXPLAIN ANALYZE additionally requires allow_explain_analyze=true
metadata schema access requires allow_metadata=true
```

이 boundary는 DB 권한을 대체하지 않습니다. 최종 안전망은 항상 DB role 권한과
Postgres read-only transaction입니다.

## 5. target execution boundary

역할:

```text
정책을 통과한 read-only SQL을 Postgres에서 제한된 시간 안에 실행
```

불변조건:

```text
endpoint only from credential row
password only from sealed secret
execution uses Postgres read-only transaction
timeout enforced
row iteration stops at max_rows
```

실패 시:

```text
safe public error
query text 저장 없음
params values 저장 없음
result values 저장 없음
audit/history outcome=error or denied
```

## 6. output shape / budget boundary

역할:

```text
DB 결과 행렬을 LLM이 소비하기 쉬운 작은 JSON envelope으로 변환
```

지원 shape:

```text
rows     -> 행 의미가 중요한 기본 형태
columns  -> 여러 행 비교에서 키 반복을 줄이는 형태
values   -> 정확히 한 컬럼만 선택했을 때 가장 작은 형태
```

불변조건:

```text
shape=values requires exactly one result column
Postgres json/jsonb and array values return as proper JSON values
large cell values are compacted
max_bytes overrun returns truncated=true + more hints
returned values are not written to history/audit
```

## 7. audit / history boundary

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
query_sha256
params_count
shape
max_rows
max_bytes
timeout_ms
purpose
outcome
latency_ms
row_count
returned_bytes
truncated
result_columns
error_kind
safe error message
```

저장 금지:

```text
query text
params values
result values
secret values
endpoint URL
raw driver error with endpoint/secret risk
```

## Current closure assessment

현재 구현 기준:

```text
input boundary: mostly closed
identity/role boundary: closed
credential/policy boundary: mostly closed
SQL AST policy boundary: mostly closed
target execution boundary: mostly closed
output shape/budget boundary: mostly closed
audit/history boundary: mostly closed, live MCP smoke remains valuable
```
