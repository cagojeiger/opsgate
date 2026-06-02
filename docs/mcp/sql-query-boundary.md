# sql_query boundary 모델

이 문서는 `sql_query` 고유의 닫힌 boundary 모델을 정의합니다. `api_call`은
HTTP/JSON 응답을 다루지만, `sql_query`는 Postgres 데이터베이스에 대해
읽기 전용 SQL을 실행하고 결과 행렬을 작은 JSON envelope으로 변환합니다.

`sql_query`의 목표는 LLM이 DB password와 `database_url`을 보지 않은 채 등록된
Postgres credential을 안전하게 사용하고, 필요한 만큼만 결과를 가져오게
하는 것입니다.

테이블/컬럼 구조를 모를 때는 먼저 `sql_schema`를 사용합니다. `sql_schema`는
row 값을 반환하지 않고 고정 JSON 구조만 반환합니다. `sql_query`는 SQL 행렬을
column-oriented JSON으로 전치한 뒤 `api_call`과 같은 JSON 출력 공통 유틸리티를
사용합니다.

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
database_url leak
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
identity
  ↓
credential / policy
  ↓
SQL AST policy
  ↓
target execution
  ↓
output / budget
  ↓
audit / history
```

## 1. input boundary

역할:

```text
LLM이 준 SQL 요청이 sql_query 표면에 들어와도 되는 모양인지 확인
```

대상 입력:

```text
alias
purpose
query
params
jsonpath
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
jsonpath uses the shared safe subset, including RFC 9535-compatible `match()`/`search()` filters and `.length()`/`.count()` count suffixes
max_rows range 1..1000
max_bytes range 1024..1MiB
timeout_ms range 1..30000
```

이 단계의 한도는 credential policy와 무관한 절대 상한입니다. policy가 더
낮은 cap을 지정했는지는 별도의 credential / policy boundary에서 검사합니다.
입력이 비어 있으면 적용되는 기본값은 다음과 같습니다.

```text
jsonpath default empty
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
LLM still has no database_url
LLM still has no password
request budget is inside SQL policy
```

중요한 설계:

```text
opsgate는 일반적인 schema whitelist 정책을 두지 않습니다.
등록된 database_url이 데이터베이스 경계를 선택합니다.
DB role grant가 접근 가능한 테이블을 결정합니다.
```

단, Postgres metadata 영역은 별도 정책 축입니다.

```text
pg_catalog / information_schema 접근은 allow_metadata=true가 필요합니다.
이것은 metadata gate이며 일반적인 schema whitelist가 아닙니다.
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
metadata schema 접근은 `allow_metadata=true`가 필요
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
database_url only from credential row
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
policy/parser denied history는 raw SQL 조각 대신 generic safe message 기록
```

## 6. output / budget boundary

역할:

```text
DB 결과 행렬을 LLM이 소비하기 쉬운 작은 column-oriented JSON으로 변환
```

출력 모델:

```text
SQL rows -> column-oriented body
jsonpath -> projection over the column-oriented body, with `.length()`/`.count()` for count-only answers
max_bytes overrun -> body=null + more hints
```

불변조건:

```text
Postgres json/jsonb and array values return as proper JSON values
row_count means fetched SQL rows after max_rows enforcement
partial JSON is never returned
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

`sql_query`의 policy/parser 거부는 클라이언트 응답에는 실행 가능한 검증 메시지를
반환할 수 있지만, history에는 raw SQL 조각이 섞일 위험을 피하기 위해 generic
safe message(`sql query denied by credential policy`)만 저장합니다. SQL 실행 중
Postgres가 반환한 알려진 SQLSTATE는 `sql_undefined_column` 같은 safe kind/message로
기록하고, 내부 driver error는 generic message로 축약합니다.

저장 금지:

```text
query text
params values
result values
secret values
database_url
raw driver error with database_url/secret risk
```

## 현재 구현 상태

현재 구현 기준:

```text
input boundary: validation test로 닫혀 있음
identity boundary: 닫혀 있음
credential/policy boundary: policy test로 닫혀 있음
SQL AST policy boundary: AST policy test로 닫혀 있음
target execution boundary: guard test로 닫혀 있음
output/budget boundary: output test로 닫혀 있음
audit/history boundary: 단위/통합 테스트로 닫혀 있으며 live 스모크도 유효함
```
