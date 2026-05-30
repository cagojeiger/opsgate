# MCP 도구 worst-case 설계와 TC 매트릭스

이 문서는 opsgate MCP 도구가 최악의 입력, 최악의 target 응답, 반복 호출,
기록 폭증 상황에서도 작게 실패하도록 만드는 불변조건과 테스트 케이스를
정의합니다.

결론부터 말하면, 이 문서는 “모든 미래 케이스를 완전히 증명하는 닫힌
논리”가 아닙니다. 대신 각 boundary별로 닫힌 불변조건을 만들고, 새 기능이
추가될 때 이 매트릭스에 TC를 추가하는 방식으로 닫힌 체계에 가깝게
운영합니다.

핵심 원칙:

```text
opsgate tools must fail small.
```

최악의 경우에도:

```text
응답은 작게
실패 메시지는 안전하게
다음 행동 힌트는 명확하게
body/secret/value는 저장하지 않게
target 재호출은 최소화하게
```

## 닫힌 boundary 모델

각 도구는 다음 boundary를 통과합니다.

```text
1. input boundary
2. identity boundary
3. credential/policy boundary
4. target execution boundary
5. response envelope / output shape boundary
6. audit/history boundary
7. future cache boundary
```

각 boundary마다 불변조건을 둡니다.

```text
input:
  길이, 개수, 형식, 상호배타 조건을 검증한다.

identity:
  미인증/비활성 사용자를 명확히 거절한다.
  권한 경계는 role이 아니라 /mcp와 /mcp/admin의 도구 노출로 표현한다.

credential/policy:
  alias/category/provider mismatch를 거절한다.
  policy 밖 method/request_path/header/query/SQL 실행을 거절한다.

target execution:
  timeout, SSRF, read-only transaction, redirect, DNS rebinding을 방어한다.

response envelope:
  invalid JSON, oversized JSON, nested/token 폭탄을 작게 반환한다.
  SQL 결과는 column-oriented body와 byte budget으로 작게 반환한다.

audit/history:
  body, secret, target URL, query value, SQL params value를 저장하지 않는다.

future cache:
  원본 body를 저장하지 않는다.
  TTL/owner/caller/request binding을 둔다.
```

## hard limits

현재 코드 기준 주요 제한:

| 영역 | 제한 |
|---|---:|
| `api.call.max_bytes` 기본값 | 4096 |
| `api.call.max_bytes` 최소/최대 | 256 / 1 MiB |
| `api.call` hard read cap | 1 MiB |
| `api.call.jsonpath` 최대 개수 | 16 |
| `api.call.jsonpath` 최대 길이 | 512 |
| `api.call.headers` 최대 개수 | 16 |
| `api.call.header value` 최대 길이 | 1024 |
| `purpose` 길이 | 8-512, CR/LF 금지 |
| `sql.query.max_rows` 기본/최대 | 100 / 1000 |
| `sql.query.max_bytes` 기본/최대 | 64 KiB / 1 MiB |
| `sql.query.timeout_ms` 기본/최대 | 3000 / 30000 |
| `sql.query` query 최대 길이 | 16000 |
| `sql.query.params` 최대 개수 | 64 |
| `credential.list.limit` 기본/최대 | 50 / 100 |
| `credential.list.fields` 최대 개수 | 8 |
| `credential.tags` 최대 개수 | 16 |
| HTTP secret header value 최대 길이 | 8192 |

## api.call worst cases

### WC-API-01: target이 매우 큰 JSON을 반환

상황:

```text
target returns 100MB valid JSON
LLM did not provide jsonpath
```

기대:

```text
read cap에서 중단
body=null
more.truncated=true
more.options.preferred_next=jsonpath
partial JSON 반환 없음
response body 저장 없음
```

TC:

```text
unit: buildEnvelope transportTruncated=true
unit/integration: target body > MaxMaxBytes
assert body == null
assert more.truncated
assert preferred_next=jsonpath
assert history has no body
```

현재 상태:

```text
부분 구현됨. transportTruncated=true envelope TC 존재.
```

### WC-API-02: valid JSON이지만 max_bytes 초과

상황:

```text
target response <= hard cap
compact body > max_bytes
```

기대:

```text
body=null
more.truncated=true
suggested_max_bytes 가능하면 제공
jsonpath hint 제공
```

TC:

```text
unit: TestBuildEnvelopeTruncatedReturnsNullBody
assert no partial JSON
```

현재 상태:

```text
구현됨.
```

### WC-API-03: top-level scalar JSON

상황:

```json
9223372036854775807
```

기대:

```text
valid JSON으로 반환
MCP schema validation 통과
큰 숫자 정밀도 보존
```

TC:

```text
unit: top-level scalar JSON
tool schema: body allows string/number/bool/null
```

현재 상태:

```text
구현됨.
```

### WC-API-04: JSONPath가 너무 많거나 복잡함

상황:

```text
jsonpath 100개
jsonpath 길이 10KB
$..recursive
script extension
```

기대:

```text
bad_input으로 거절
target 호출 없음
audit/history에는 denial만 기록
```

TC:

```text
unit: too many jsonpath
unit: overlong jsonpath
unit: unsupported fragment
```

현재 상태:

```text
부분 구현됨. mutual exclusion과 valid JSONPath TC 존재.
추가 negative TC 필요.
```

### WC-API-05: header 우회

상황:

```text
Authorization/Cookie/Host/X-Forwarded-* override
secret header와 같은 이름 override
```

기대:

```text
거절
secret header 덮어쓰기 불가
target 호출 없음
```

현재 상태:

```text
구현/TC 존재.
```

### WC-API-06: target이 non-JSON 또는 깨진 JSON 반환

기대:

```text
response_envelope_failed
body 없음
safe public error
```

현재 상태:

```text
구현/TC 존재.
```

## sql.query worst cases

`sql.schema`는 `sql.query` 전에 사용하는 구조 조회 도구입니다. row 값을
반환하지 않지만, 출력 크기와 metadata 노출을 별도 boundary로 다룹니다.

### WC-SQL-01: huge table scan

상황:

```sql
select * from huge_table
```

기대:

```text
max_rows로 row 제한
max_bytes 초과 시 body=null + more hint 반환
truncated=true
명시적 컬럼/WHERE/count/group 또는 jsonpath로 재시도 유도
```

현재 상태:

```text
구현/일부 TC 존재.
```

### WC-SQL-02: write/DDL/lock/function abuse

상황:

```sql
insert/update/delete/drop
select ... for update
select pg_sleep(10)
select current_user
explain analyze ...
```

기대:

```text
AST/policy gate에서 실행 전 거절
read-only transaction이 최종 안전망
```

현재 상태:

```text
구현됨. 추가 통합 TC 유지 필요.
```

### WC-SQL-03: 큰 단일 cell 또는 큰 JSON 컬럼

상황:

```sql
select huge_jsonb_or_text from table
```

기대:

```text
column-oriented body 생성 후 공통 JSON output budget 적용
max_bytes 초과 시 partial JSON 없이 body=null
more.options.preferred_next=jsonpath 또는 narrow_jsonpath
raw huge cell 전체를 audit/history에 저장하지 않음
```

현재 상태:

```text
구현됨. 공통 JSON output envelope TC로 보호한다.
```

### WC-SQL-04: JSONPath projection 오용

상황:

```text
jsonpath가 safe subset 밖이거나 너무 많음
jsonpath가 유효하지만 projection 결과가 여전히 큼
```

기대:

```text
invalid jsonpath는 실행 전 bad_input으로 거절
큰 projection은 body=null + narrow_jsonpath hint
결과 값은 history/audit에 저장하지 않음
```

현재 상태:

```text
구현/TC 존재.
```

### WC-SQL-05: schema inspection leaks row data or explodes output

상황:

```text
LLM does not know table names and calls sql.schema
database has many tables or a table has many columns/indexes
```

기대:

```text
fixed JSON envelope only
no row values
no connection string/password
tables mode is paginated
table mode omits indexes by default
max_bytes truncates table detail and returns hints
```

현재 상태:

```text
구현/기본 TC 존재. live DB smoke로 추가 검증할 가치 있음.
```

## credential.list worst cases

### WC-LIST-01: credential 수가 매우 많음

기대:

```text
default limit 50
max limit 100
cursor pagination
fields projection
secret/target URL 미반환
```

현재 상태:

```text
구현/TC 존재.
```

## credential.register/update worst cases

### WC-CRED-01: private/internal target 등록

기대:

```text
allow_private_network=false이면 register-time DNS 검증으로 거절
call-time dial에서도 재검증
```

현재 상태:

```text
구현/TC 존재.
```

### WC-CRED-02: update로 secret/target URL 변경 시도

기대:

```text
update input 자체에 secret/target URL 필드 없음
secret rotation/target change는 delete + register
```

현재 상태:

```text
구현/TC 존재.
```

### WC-CRED-03: policy full replacement 실수

상황:

```text
LLM이 일부 policy만 보내 기존 policy가 사라짐
```

기대:

```text
도구 설명과 문서에서 full replacement를 명시
가능하면 future: dry-run/preview 또는 changed_paths
```

현재 상태:

```text
문서화됨. preview/dry-run은 미구현.
```

## credential.delete worst cases

### WC-DEL-01: LLM이 실수로 삭제

기대:

```text
/mcp/admin 관리 서피스에만 노출
reason required
tool description requires explicit user confirmation
soft-delete + secret cryptoshred
history append
```

현재 상태:

```text
구현됨. challenge-confirmation은 미구현.
```

## audit/history worst cases

### WC-AUDIT-01: body/secret/value가 저장됨

기대:

```text
request body 저장 금지
response body 저장 금지
secret 저장 금지
query value 저장 금지
SQL params value 저장 금지
api.call projection_keys에는 JSONPath 표현식만 저장
sql.query result_columns에는 컬럼명만 저장
```

현재 상태:

```text
대부분 구현됨.
회귀 TC를 강화할 가치 있음.
```

### WC-AUDIT-02: reason 키 의미 충돌

기대:

```text
denial_reason
update_reason
delete_reason
error_kind
reason 키 신규 사용 금지
```

현재 상태:

```text
수정됨. 회귀 TC 필요.
```

### WC-AUDIT-03: wrong-tool denial loses credential metadata

상황:

```text
api.call(alias=<sql credential>)
sql.query(alias=<http credential>)
```

기대:

```text
denied
error_kind/denial reason identifies wrong credential category/provider
history keeps credential id/alias/category/provider/env snapshot
history still stores no body/query/params/result/secret/target URL values
```

현재 상태:

```text
구현/서비스 TC 존재.
live MCP smoke로 재확인할 가치 있음.
```

## preview/cache worst cases

### WC-PREVIEW-01: preview가 또 다른 토큰 폭탄이 됨

기대:

```text
max_preview_bytes
max_preview_paths
max_preview_depth
max_array_sample
max_nested_array_expansion
examples 기본 off
```

현재 상태:

```text
구현됨. preview path catalog와 budget enforcement, nested array marker, TC 모두 존재.
```

### WC-PREVIEW-02: preview pagination이 다른 snapshot을 섞음

기대:

```text
pagination을 제공하려면 preview_id 기반 cache 필수
cache에는 원본 body 저장 금지
path catalog와 통계만 저장
TTL 짧게
owner/caller/request_id binding
```

현재 상태:

```text
0.1.0에서는 pagination 없음으로 결정.
미래 기능으로만 문서화.
```

## TC 우선순위

0.1.0 전에 추가하면 좋은 TC:

```text
P0:
  api.call jsonpath unsupported fragment rejects before target call
  api.call too many jsonpath rejects
  api.call transportTruncated never parses broken prefix
  audit/history never stores api response body after jsonpath/truncation
  api.call/sql.query wrong-tool history keeps credential metadata snapshot

P1:
  sql.query denied SQL value functions remain denied
  sql.query large cell/output truncation returns body=null within max_bytes
  credential.update policy full replacement behavior is explicit
  audit detail has no generic reason key for new events

P2:
  preview path catalog budget regression tests (preview는 이미 구현/TC 존재)
  preview cache authorization tests if pagination is implemented
```

## 판단

현재 worst-case 설계는 “완전히 닫힌 수학적 증명”은 아니지만, boundary별
불변조건으로 닫힌 체계에 가깝게 만들 수 있습니다.

닫힌 체계로 운영하려면 새 기능 추가 시 반드시 다음을 갱신합니다.

```text
1. worst-case 항목
2. hard limit
3. audit/history 저장 금지 항목
4. TC
```
