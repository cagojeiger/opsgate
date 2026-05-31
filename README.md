# opsgate

Rust backend 중심의 개인용 MCP/REST broker입니다. LLM client가 직접 secret을 보지
않고, 등록된 credential policy 안에서 HTTP/API 호출과 SQL 조회를 수행하도록 합니다.

## 구조

```text
opsgate/
├─ Cargo.toml              # workspace root: 공통 deps/lints/profile
├─ rust-toolchain.toml     # Rust 1.95.0 고정
├─ backend/crates/
│  ├─ api/                 # Axum 서버, REST/MCP adapter, auth/login/bootstrap
│  ├─ service/             # credential/api.call/sql.query/sql.schema 유스케이스
│  ├─ infra/               # 외부 HTTP/Postgres target client/cache/guard
│  ├─ db/                  # 내부 Postgres repo + migration
│  ├─ model/               # 공통 타입과 순수 validation/policy
│  └─ core/                # 최소 공통 Error/Result/schema/tls/validation helper
├─ backend/Dockerfile      # cargo-chef multi-stage, non-root Debian runtime
├─ docker-compose.yml      # postgres + api
├─ docs/                   # 현재 구현 기준 문서
└─ frontend/               # 추후 구현
```

## 로컬 개발

```sh
# 1. Postgres 실행
docker compose up -d postgres

# 2. 환경 파일 준비
cp .env.example .env

# 3. API 실행: 시작 시 migration 적용
cargo run --bin opsgate-api
```

상태 확인:

```sh
curl localhost:9091/health
curl localhost:9091/ready
```

## 인증/MCP 기본값

`.env.example` 기준 기본값:

- `OPSGATE_AUTHGATE_URL=https://authgate.project-jelly.io`
- `OPSGATE_PUBLIC_URL=http://localhost:9091`
- `OPSGATE_OAUTH_CLIENT_ID=opsgate-web`
- `OPSGATE_OAUTH_REDIRECT_URL=http://localhost:9091/callback`
- `OPSGATE_RESOURCE_URL=http://localhost:9091/mcp`

최초 사용자는 `${OPSGATE_PUBLIC_URL}/login`을 한 번 열어 authgate 로그인을 완료해야
로컬 opsgate user row가 생성됩니다. 이후 MCP client를 `OPSGATE_RESOURCE_URL`에
연결합니다.

현재 인증 구조:

```text
JWT 검증: auth::jwt::JwtAuthority가 API/MCP 공통으로 수행
/api/*: API adapter + 일반 Bearer challenge
/mcp, /mcp/admin: MCP adapter + scoped Bearer challenge
/login, /callback: 브라우저 OAuth login + user upsert
```

## 검증

```sh
make release-check
```

릴리스 및 MCP smoke 절차는 `docs/release-checklist.md`에 있습니다.

## Docker 전체 실행

```sh
docker compose up --build
```
