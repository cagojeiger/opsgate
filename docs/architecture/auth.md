# 인증 구조

이 문서는 현재 Rust 구현의 인증 경계를 기록합니다. 미래 계획이 아니라 현재 코드가
따르는 구조입니다.

## 핵심 원칙

```text
JWT 검증은 하나의 검증 서비스로 통일한다.
API, MCP, Login은 각 프로토콜에 맞는 얇은 어댑터로 남긴다.
사용자 생성은 브라우저 Login 경로에서만 수행한다.
```

## 모듈 책임

```text
backend/crates/api/src/auth/
├─ jwt.rs       # aliri_oauth2 기반 JWT 검증 서비스
├─ api.rs       # /api/* Bearer 인증 adapter
├─ mcp.rs       # /mcp, /mcp/admin 인증 adapter
├─ bearer/      # Bearer extractor와 공통 AuthError/response
├─ oauth.rs     # /login, /callback 브라우저 OAuth 흐름
├─ oidc.rs      # authgate OIDC metadata/JWKS snapshot cache
└─ metadata.rs  # OAuth protected-resource / authorization-server metadata
```

### `auth::jwt`

`auth::jwt::JwtAuthority`가 API와 MCP의 공통 JWT 검증 서비스입니다.

책임:

- JWKS lazy fetch/cache
- `RS256` 검증
- issuer 검증
- audience 검증
- audience trailing slash 호환
- 만료/표준 claim 검증
- unknown `kid` 발생 시 JWKS refresh 후 재검증
- `sub`, `email`, `name`을 `ResolveAttrs`로 변환

`JwtAuthority`는 서버 부팅 시 authgate `/keys`를 호출하지 않습니다. 첫 Bearer 인증
요청에서 필요할 때 JWKS를 가져옵니다.

### `auth::api`

`/api/*` 전용 axum middleware입니다.

흐름:

```text
Authorization Bearer 추출
→ JwtAuthority.verify(token)
→ resolve_api(attrs)
→ Caller extension 삽입
→ REST handler 실행
→ API request audit 기록
```

API 인증 실패 응답은 일반 Bearer challenge를 사용합니다.

### `auth::mcp`

MCP request를 `rmcp` 서비스에 넘기기 전에 호출되는 전처리 adapter입니다.

흐름:

```text
Authorization Bearer 추출
→ JwtAuthority.verify(token)
→ resolve_mcp(attrs)
→ Request extensions에 Caller 삽입
→ rmcp service.handle(request)
```

MCP 인증 실패 응답은 MCP client가 재인증할 수 있도록 scoped Bearer challenge를
사용합니다. `/mcp`와 `/mcp/admin`은 role/admin 권한 게이트가 아니라 노출되는 도구
목록으로 분리됩니다.

### `auth::oauth`

브라우저 기반 최초 Login 흐름입니다.

흐름:

```text
/login
→ authgate authorization redirect
→ /callback
→ code exchange + userinfo 검증
→ resolve_browser(attrs)
→ users row upsert
```

브라우저 검증은 Bearer 검증과 별도의 discovery/JWKS snapshot을 사용합니다.
Discovery TTL은 3600초이며, 만료 후 조회에 실패하면 기존 snapshot을 유지합니다.
처음부터 snapshot이 없고 조회에 실패하면 로그인도 실패합니다. 이 TTL은 오래된 키를
반드시 제거하는 최대 수명 제한이 아닙니다.

Callback의 ID token에서 일치하는 키가 없거나 서명이 맞지 않으면, 검증된 discovery의
`jwks_uri`에서 키를 한 번 갱신하고 같은 ID token을 재검증합니다. Authorization code는
다시 교환하지 않습니다. 갱신 후에도 issuer, audience, nonce, 만료, `at_hash`와 UserInfo
subject 검증을 모두 적용합니다. 다른 claim 오류는 키 재조회를 유발하지 않습니다.
JWKS 갱신은 discovery TTL을 연장하지 않으며, 실패하면 기존 cache를 보존하고 해당
callback은 실패합니다. 동시 요청은 discovery와 JWKS 조회를 직렬화하고 같은 조회 시도의
성공 또는 실패를 공유합니다. Bearer의 300초 기본 갱신 주기와 unknown-`kid` 처리는
독립적입니다.

`/api`, `/mcp`, `/mcp/admin`은 사용자를 생성하지 않습니다. 인증된 authgate 계정이
opsgate에 아직 등록되어 있지 않으면 `not_registered`로 거부하며, 사용자는 `/login`을
한 번 열어 로컬 user row를 만들어야 합니다.

## 사용자 resolve 정책

`opsgate-model`의 resolver가 channel별 정책을 가집니다.

```text
Browser/Login  → resolve_browser → user upsert 후 active 확인
API            → resolve_api     → registered + active user만 허용
MCP            → resolve_mcp     → registered + active user만 허용
```

inactive user는 모든 인증 surface에서 거부됩니다.

## 의존성 기준

- production JWT 검증은 `aliri`/`aliri_oauth2`를 사용합니다.
- `jsonwebtoken`은 production dependency가 아닙니다. 테스트 토큰 생성용
  dev-dependency로만 사용합니다.
- TLS는 rustls 계열을 사용하며 OpenSSL 계열 의존성을 끌어오지 않습니다.

