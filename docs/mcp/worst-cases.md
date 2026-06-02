# MCP 도구 최악 상황 방어 기준

이 문서는 현재 Rust 구현이 MCP 도구의 최악 입력, 큰 target 응답, 기록 폭증,
시크릿 노출 위험을 어떻게 작게 실패시키는지 정리합니다. 미래 기능 계획이나
미완료 TODO가 아니라, 현재 코드 기준의 불변조건만 기록합니다.

핵심 원칙:

```text
opsgate 도구는 작게 실패해야 한다.
```

최악의 경우에도 다음을 지켜야 합니다.

```text
응답은 작게 반환한다.
실패 메시지는 안전한 reason/kind만 노출한다.
다음 행동 힌트는 구조화해서 제공한다.
body, secret, target URL, SQL params 값은 history/audit에 저장하지 않는다.
target 재호출이 필요한 경우 LLM이 더 좁은 요청을 만들 수 있게 안내한다.
```

## 공통 경계

```text
1. input boundary
2. identity boundary
3. credential/policy boundary
4. target execution boundary
5. response/output boundary
6. audit/history boundary
```

### 입력

- 길이, 개수, 형식, 상호배타 조건을 먼저 검증합니다.
- 실패하면 credential lookup, secret open, target execution을 하지 않습니다.
- bad input도 안전한 alias와 reason만 audit/history에 남깁니다.

### 신원

- REST와 MCP 모두 같은 JWT 검증 서비스(`auth::jwt::JwtAuthority`)를 통과한 Bearer 인증 사용자가 필요합니다.
- `/login`/`/callback`만 로컬 user row를 생성하거나 갱신합니다. REST와 MCP는 registered + active user만 허용합니다.
- inactive 사용자는 거부됩니다.
- `/mcp`와 `/mcp/admin`의 차이는 role이 아니라 노출되는 도구 목록입니다.

### credential/policy

- alias는 항상 owner user 범위에서 조회합니다.
- category/provider mismatch는 실행 전에 거부합니다.
- HTTP method/path/query/header와 SQL row/byte/time budget은 credential policy 안에서만 허용합니다.
- LLM은 target URL 구성값과 secret 값을 받지 않습니다.

### target 실행

- HTTP는 redirect를 따르지 않습니다.
- HTTP target은 Content-Type이 JSON인지 body read 전에 확인합니다.
- HTTP와 SQL 모두 private/link-local/loopback target은 기본 차단되며, 내부 target은 명시적 opt-in이 필요합니다.
- SQL은 Postgres read-only transaction으로 실행됩니다.

### response/output

- 깨진 JSON이나 partial JSON 문자열을 반환하지 않습니다.
- 큰 JSON은 `body=null`, `truncated=true`, `more` 힌트로 반환합니다.
- `api_call`과 `sql_query`는 JSONPath projection을 지원합니다.
- 개수 질문은 전체 배열을 반환하지 않고 `.length()`/`.count()` suffix로 작게 답할 수 있습니다.
- `sql_query`는 행 배열을 그대로 반환하지 않고 column-oriented JSON으로 반환합니다.
- `sql_schema`는 row 값을 반환하지 않고 schema metadata만 반환합니다.

### audit/history

저장 가능한 것:

```text
actor / owner
channel
request_id
credential id/alias/category/provider/env snapshot
method 또는 query_sha256
query/header/projection key 이름
budget 값
purpose
outcome
latency/bytes/row count/truncated
safe error kind/message
```

예외적으로 raw dependency error는 저장하지 않습니다. HTTP target 전송 실패는
opsgate가 분류한 `target_timeout`/`target_unreachable`/`target_private_network_blocked`
같은 안전한 kind만 기록하고, SQL policy/parser 거부는 raw SQL 조각을 피하기 위해
generic safe message로 기록합니다.

저장 금지:

```text
request body
response body
query value
header value
secret value
SQL params value
SQL result value
target URL 구성값(origin/base_path/database_url)
raw dependency error 중 URL/secret이 섞일 수 있는 값
```

## 현재 하드 제한

| 영역 | 제한 |
|---|---:|
| `api_call.max_bytes` 기본값 | 4096 |
| `api_call.max_bytes` 최소/최대 | 256 / 1 MiB |
| `api_call` hard read cap | 1 MiB |
| `api_call.jsonpath` 최대 개수 | 16 |
| `api_call.jsonpath` 최대 길이 | 512 |
| `api_call.headers` 최대 개수 | 16 |
| `api_call.header value` 최대 길이 | 1024 |
| `purpose` 길이 | 8-512, CR/LF 금지 |
| `sql_query.max_rows` 기본/최대 | 100 / 1000 |
| `sql_query.max_bytes` 기본/최대 | 64 KiB / 1 MiB |
| `sql_query.timeout_ms` 기본/최대 | 3000 / 30000 |
| `sql_query` query 최대 길이 | 16000 |
| `sql_query.params` 최대 개수 | 64 |
| `sql_schema.limit` 기본/최대 | 50 / 100 |
| `credential_list.limit` 기본/최대 | 50 / 100 |
| `credential_list.fields` 최대 개수 | 8 |
| `credential.tags` 최대 개수 | 16 |
| HTTP secret header value 최대 길이 | 8192 |

## 도구별 최악 상황 동작

### `api_call`

큰 JSON 응답:

```text
body=null
truncated=true
more.options.preferred_next=jsonpath 또는 narrow_jsonpath
partial JSON 반환 없음
response body 저장 없음
```

비 JSON 응답:

```text
body read 전에 error
response body 저장 없음
```

금지 header/query/path/method:

```text
denied
target call 없음
secret header override 불가
```

### `sql_query`

위험 SQL:

```text
single SELECT/WITH 또는 정책이 허용한 EXPLAIN만 허용
write/lock/side-effect 함수/metadata 접근은 정책에 따라 거부
실행은 read-only transaction 내부에서 수행
```

큰 결과:

```text
row limit에 걸리면 more.options.preferred_next=max_rows
byte limit에 걸리면 body=null + jsonpath/query narrowing hint
query text, params 값, result 값 저장 없음
```

### `sql_schema`

큰 schema 출력:

```text
max_bytes를 넘으면 indexes, primary_key, columns, table list 순서로 줄인다.
row 값은 반환하지 않는다.
secret/database_url은 반환하지 않는다.
```

### `credential.*`

등록:

```text
normalize/validate
target IP guard
secret seal
DB insert + credential history
```

수정:

```text
description/env/tags/policy만 변경 가능
policy는 병합이 아니라 전체 교체
secret과 target은 변경 불가
HTTP policy가 sealed secret header와 겹치면 거부
```

삭제:

```text
/mcp/admin 전용
reason required
soft delete
secret_ciphertext=NULL
secret_destroyed_at 기록
history append
```

## 현재 검증 게이트

문서 동기화 시점의 로컬 게이트:

```sh
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

신규 DB/compose 스모크:

```text
0001 schema migration success
0002 runtime least privilege migration success
/health 200
/ready 200
unauthenticated /api/v1/me 401
```
