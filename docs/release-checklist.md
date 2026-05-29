# 0.1.0 release readiness checklist

날짜: 2026-05-21

현재 target:

```text
0.1.0 release candidate
```

## 상태

```text
release-check: PASS
```

명령:

```text
make release-check
```

`release-check`가 다루는 항목:

```text
go test ./...
go vet ./...
go build -o bin/opsgate ./cmd/opsgate
govulncheck ./...
deadcode -test ./...
staticcheck ./...
git diff --check
```

## 준비 점검 중 수정한 사항

```text
Makefile:
  release-check now runs govulncheck with GOTOOLCHAIN=go1.26.3,
  matching the module's Go version and the other analyzer commands.

internal/service/sql/query/run_test.go:
  removed an unused test helper that deadcode/staticcheck reported.
```

## 검증한 surface

```text
/mcp runtime:
  me
  credential.list
  api.call
  sql.schema
  sql.query

/mcp/admin:
  me
  credential.register_http
  credential.register_sql
  credential.update_http
  credential.update_sql
  credential.list
  credential.delete
```

## 남은 release 참고 사항

```text
첫 0.1.0 release 전까지는 changelog를 유지하지 않습니다.
Preview pagination/cache는 0.1.0에 의도적으로 포함하지 않습니다.
실제 authgate live 로그인과 실 target API smoke는 environment 레벨 점검으로 남겨 둡니다.
```
