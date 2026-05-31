# 크레이트 경계와 의존성 설계

이 문서는 현재 Rust 구현을 기준으로, `api` 크레이트 비대화와 컴파일 캐시 효율 문제를 줄이기 위한 목표 구조를 정의합니다.
운영 배포 전 리팩토링 기준 문서이며, 새 기능 명세가 아니라 코드 배치와 의존성 규칙을 고정하는 문서입니다.

## 문제 정의

현재 `opsgate-api`는 HTTP/MCP 노출 계층뿐 아니라 인증, credential 유스케이스, SQL/API 실행 유스케이스, 외부 HTTP/Postgres 연결, audit 조립까지 포함합니다.
이 구조는 다음 문제가 있습니다.

- MCP 도구 설명이나 REST 핸들러를 바꿔도 큰 `api` 크레이트가 자주 흔들립니다.
- `axum`, `rmcp`, `openidconnect`, `reqwest`, `sqlx`, `sqlparser` 같은 무거운 의존성이 한 크레이트에 모여 있습니다.
- transport 코드와 service 로직, 외부 연결 infra 코드의 책임 경계가 코드 구조에서 잘 보이지 않습니다.
- `domain`이라는 이름이 현재 역할보다 무겁고, 실제로는 공통 모델과 순수 정책/검증에 가깝습니다.

## 설계 원칙

1. `api`는 외부 노출 계층만 담당합니다.
2. `service`는 credential, api.call, sql.query, sql.schema 유스케이스 흐름을 담당합니다.
3. `infra`는 credential로 등록된 외부 HTTP/Postgres 대상에 연결하는 코드만 담당합니다.
4. `db`는 opsgate 내부 Postgres 저장소만 담당합니다.
5. `model`은 공통 타입과 순수 정책/검증만 담당합니다.
6. `core`는 모든 계층이 써도 되는 최소 기반만 담당합니다.
7. 자주 바뀌는 코드가 낮은 레이어에 들어가지 않도록 합니다.
8. 컴파일 캐시 효율을 위해 무거운 의존성은 필요한 크레이트에만 둡니다.

## 목표 크레이트

```text
backend/crates/
├─ api
├─ service
├─ infra
├─ db
├─ model
└─ core
```

### `opsgate-api`

역할:

- `main` / bootstrap
- axum route
- REST handler
- MCP server/tool adapter
- OAuth callback
- bearer extractor/middleware
- HTTP/MCP error mapping

허용 의존성:

- `axum`
- `rmcp`
- `tower`, `tower-http`
- `openidconnect`, `jsonwebtoken`, `axum-extra`
- `opsgate-service`, `opsgate-db`, `opsgate-model`, `opsgate-core`

금지:

- credential 등록/수정/삭제의 핵심 흐름 직접 구현
- SQL query policy/executor 직접 구현
- 외부 HTTP/Postgres 호출 구현

### `opsgate-service`

역할:

- `credential.register/list/update/delete`
- `api.call`
- `sql.query`
- `sql.schema`
- secret seal/open 흐름
- policy 검증 흐름
- audit/history 기록 순서 조립
- LLM-facing JSON output 조립

허용 의존성:

- `opsgate-db`
- `opsgate-infra`
- `opsgate-model`
- `opsgate-core`
- `sqlparser`, `serde`, `serde_json`, `schemars`, `secrecy`

금지:

- `axum`
- `rmcp`
- `openidconnect`
- route/extractor/cookie/session 처리

### `opsgate-infra`

역할:

- credential 대상 외부 HTTP client/cache
- credential 대상 외부 Postgres pool/cache
- DNS/IP/private network guard
- TLS/CA 처리
- HTTP/Postgres transport error를 내부 `Error`로 안전하게 변환

허용 의존성:

- `reqwest`
- `sqlx`
- `tokio`
- `url`
- TLS/network 관련 crate
- `opsgate-model`, `opsgate-core`

금지:

- `opsgate-db`
- `opsgate-service`
- `axum`
- `rmcp`

중요 규칙:

```text
service가 db에서 credential을 조회한다.
service가 secret을 열고 policy를 확인한다.
infra는 전달받은 endpoint/secret/options로 외부 호출만 수행한다.
```

### `opsgate-db`

역할:

- opsgate 내부 Postgres 연결
- SQLx repository
- migration
- history/audit 저장

허용 의존성:

- `sqlx`
- `opsgate-model`
- `opsgate-core`

금지:

- `axum`
- `rmcp`
- `reqwest`
- `openidconnect`

### `opsgate-model`

역할:

- `User`
- `Caller`, `Channel`
- `Credential`, `CredentialCategory`, `CredentialEndpoint`
- `CredentialPolicy`
- secret 입력 타입
- 순수 validation/normalization

허용 의존성:

- `serde`
- `uuid`
- `chrono`
- `secrecy`
- `url`
- `schemars`
- `opsgate-core`

금지:

- `sqlx`
- `axum`
- `rmcp`
- `reqwest`
- `openidconnect`

비고:

기존 `opsgate-domain`은 이 역할에 가까웠기 때문에, 현재 구조에서는 `opsgate-model` 이름을 사용합니다.
DDD식 풍부한 domain보다 “공통 모델과 순수 규칙”에 가까워서 `model`이 더 명확합니다.

### `opsgate-core`

역할:

- `Error`
- `Result`
- 작은 validation helper
- schema helper
- PEM 인증서 bundle 파싱 helper

원칙:

- 가장 낮은 레이어이므로 가장 작고 안정적이어야 합니다.
- `core` 수정은 전체 workspace 재컴파일을 유발하기 쉬우므로 자주 바뀌는 코드를 두지 않습니다.

현재 이동 완료:

- `config` → `api` bootstrap/config 영역
- `crypto` → `service`의 credential secret 영역
- `llm_output` → `service`의 output 영역
- `net/ssrf` → `infra` network guard

현재 유지:

- `tls`는 `model`의 credential validation과 `infra`의 HTTPS client 구성에서 함께 사용하므로, 작고 안정적인 PEM parser helper로 `core`에 남깁니다.

`common`이라는 이름은 사용하지 않습니다. 의미가 넓어져 다시 잡동사니 크레이트가 될 가능성이 높기 때문입니다.

## 목표 의존성 방향

```text
api
 ├─ service
 ├─ db
 ├─ model
 └─ core

service
 ├─ db
 ├─ infra
 ├─ model
 └─ core

infra
 ├─ model
 └─ core

db
 ├─ model
 └─ core

model
 └─ core

core
```

금지되는 역방향 의존성:

```text
model  -> service/db/infra/api
db     -> service/infra/api
infra  -> db/service/api
service -> api
core   -> any internal crate
```

## 컴파일 캐시 관점의 기대 효과

### MCP 도구 설명 또는 REST handler 수정

변경 전:

```text
opsgate-api 전체가 자주 흔들림
```

변경 후:

```text
api 중심 재컴파일
service/db/infra/model/core 캐시 유지 가능성 증가
```

### SQL 정책 또는 SQL output 수정

변경 후:

```text
service 중심 재컴파일
api는 얇은 adapter 재체크
infra/db는 변경 없으면 유지
```

### 외부 HTTP/Postgres 연결 방어 수정

변경 후:

```text
infra 중심 재컴파일
db와 api transport 영향 최소화
```

### DB query/repo 수정

변경 후:

```text
db 중심 재컴파일
infra 영향 없음
```

### core 수정

변경 후에도 전체 영향이 큽니다. 현재 `core`는 `error/schema/tls/validation`만 남긴 얇은 기반입니다. 따라서 앞으로도 자주 바뀌는 기능 코드는 `core`에 넣지 않습니다.

## 완료 기준

- `api`에는 transport/auth/bootstrap만 남습니다.
- `service`에는 유스케이스 흐름만 남고 `axum`/`rmcp` 의존성이 없습니다.
- `infra`는 외부 HTTP/Postgres 연결만 담당하고 `db`를 모릅니다.
- `db`는 내부 저장소만 담당하고 외부 HTTP client를 모릅니다.
- `model`은 순수 타입/정책/검증만 담당합니다.
- `core`는 `error/schema/tls/validation` 중심의 최소 기반만 담당합니다.
- `cargo check --workspace` 통과
- `cargo clippy --workspace --all-targets -- -D warnings` 통과
- `cargo test --workspace` 통과
