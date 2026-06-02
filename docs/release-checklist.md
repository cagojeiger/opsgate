# 0.1.0 릴리스 준비 체크리스트

기준일: 2026-05-31

대상:

```text
0.1.0 Rust 릴리스 후보 버전
```

## 현재 상태

```text
릴리스 검증: 통과
신규 DB compose 마이그레이션 스모크: 통과
```

## 필수 로컬 게이트

저장소 기본 릴리스 게이트:

```sh
make release-check
```

명시적으로는 다음 검증을 실행합니다.

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --release --bin opsgate-api
git diff --check
```

workspace는 `rust-toolchain.toml`로 Rust 1.95.0에 고정되어 있습니다. 위 게이트는
포맷, 타입 검사, 단위/통합 테스트, strict clippy/all-features, 릴리스 바이너리 빌드,
공백 안전 diff를 확인합니다.

## Postgres 기반 선택 검증

DB 테스트 일부는 `OPSGATE_TEST_DATABASE_URL`이 없으면 self-skip합니다. 마이그레이션,
runtime grant, audit 저장을 확인할 때 로컬 Postgres로 실행합니다.

```sh
docker compose up -d postgres

OPSGATE_TEST_DATABASE_URL=postgres://opsgate:opsgate@localhost:5432/opsgate \
cargo test -p opsgate-db --tests
```

runtime 최소 권한 분리를 따로 검증할 때:

```sh
OPSGATE_TEST_DATABASE_MIGRATE_URL=postgres://opsgate:opsgate@localhost:5432/opsgate \
OPSGATE_TEST_DATABASE_URL=postgres://opsgate_app:opsgate_app@localhost:5432/opsgate \
cargo test -p opsgate-db --test runtime_least_privilege -- --nocapture
```

`opsgate_app` role은 owner/migration URL이 migration을 한 번 적용한 뒤 생성됩니다.
runtime URL을 `opsgate_app`으로 먼저 연결하면 안 됩니다.

## 신규 DB compose 스모크 검증

운영 전 DB 초기화 기준 검증:

```sh
docker compose down -v
docker compose up -d postgres
docker compose up -d --build api
```

기대 결과:

```text
postgres healthy
api started
0001 schema migration success
0002 runtime least privilege migration success
```

마이그레이션 확인:

```sh
docker compose exec -T postgres \
  psql -U opsgate -d opsgate \
  -c "SELECT version, description, success FROM _sqlx_migrations ORDER BY version;"
```

기대값:

```text
1 | schema                  | true
2 | runtime least privilege | true
```

HTTP 스모크:

```sh
curl -fsS http://localhost:9091/health
curl -fsS http://localhost:9091/ready
curl -i -sS http://localhost:9091/api/v1/me
```

기대값:

```text
/health -> 200
/ready  -> 200
/api/v1/me Bearer 없음 -> 401
```

## MCP/Auth 스모크 검증

메타데이터와 미인증 MCP challenge 확인:

```sh
curl -fsS http://localhost:9091/.well-known/oauth-authorization-server
curl -fsS http://localhost:9091/.well-known/oauth-protected-resource
curl -fsS http://localhost:9091/.well-known/oauth-protected-resource/mcp
curl -i -sS http://localhost:9091/mcp -X POST -H 'content-type: application/json' -d '{}'
curl -i -sS http://localhost:9091/mcp/admin -X POST -H 'content-type: application/json' -d '{}'
```

기대값:

```text
/.well-known/oauth-authorization-server는 issuer/token/revocation/device 메타데이터를 반환
/.well-known/oauth-protected-resource는 설정된 resource 메타데이터를 반환
/.well-known/oauth-protected-resource/mcp는 `/mcp` 경로 기준 resource 메타데이터를 반환
미인증 /mcp와 /mcp/admin은 `WWW-Authenticate: Bearer` challenge와 함께 401 반환
```

인증된 live 스모크는 유효한 AuthGate 계정으로 `http://localhost:9091/login`에 한 번
접속한 뒤 MCP 클라이언트를 `http://localhost:9091/mcp`에 연결합니다.

## 검증된 서피스

```text
/mcp runtime:
  me
  credential_list
  api_call
  sql_schema
  sql_query

/mcp/admin:
  me
  credential_register_http
  credential_register_sql
  credential_update_http
  credential_update_sql
  credential_list
  credential_delete

/api/v1 REST:
  GET /api/v1/me
  POST /api/v1/api/call
  POST /api/v1/sql/query
  POST /api/v1/credentials
  GET /api/v1/credentials
  DELETE /api/v1/credentials/{alias}
```

Opsgate는 개인용 서비스입니다. `/mcp`와 `/mcp/admin`은 role/admin 게이트가
아니라 노출되는 도구 목록으로 분리됩니다.

인증 구조 기준:

```text
JWT 검증은 auth::jwt::JwtAuthority가 API/MCP 공통으로 수행합니다.
/api/*는 API adapter를 통해 일반 Bearer challenge를 반환합니다.
/mcp와 /mcp/admin은 MCP adapter를 통해 scoped Bearer challenge를 반환합니다.
/login과 /callback만 로컬 user row를 생성/갱신합니다.
```

## 남은 릴리스 메모

```text
첫 0.1.0 릴리스 전까지 별도 changelog는 유지하지 않습니다.
preview pagination/cache는 0.1.0 범위 밖입니다.
실제 target API side effect와 live Postgres query 실행은 환경 스모크 검증입니다.
```

## GitHub 릴리스 절차

Opsgate는 llmgate/authgate와 같은 VERSION 기반 릴리스 방식을 사용합니다.
릴리스 workflow는 `VERSION` 파일이 `main`에 들어올 때만 실행됩니다.

안전한 2단계 절차:

```text
1. release workflow PR merge
   - .github/workflows/release.yml만 추가
   - VERSION 파일 없음
   - 릴리스 트리거 없음

2. 실제 릴리스 PR merge
   - PR 제목: chore(release): prepare v0.1.0
   - VERSION 파일 내용: 0.1.0
   - main merge 시 v0.1.0 tag, GitHub Release, GHCR image 생성
```

릴리스 workflow가 생성하는 산출물:

```text
git tag: v0.1.0
GitHub Release: v0.1.0
GHCR image:
  ghcr.io/cagojeiger/opsgate:0.1.0
  ghcr.io/cagojeiger/opsgate:latest
```

필요 권한/시크릿:

```text
별도 secret 등록 없음
GITHUB_TOKEN 사용
workflow permissions:
  contents: write   # git tag + GitHub Release
  packages: write   # GHCR push
```

주의:

```text
VERSION을 추가하거나 변경한 PR이 main에 merge되면 즉시 릴리스가 시작됩니다.
이미 vX.Y.Z tag가 있으면 workflow는 중복 tag guard에서 실패해야 합니다.
Docker build context는 저장소 루트이고 Dockerfile은 backend/Dockerfile입니다.
```
