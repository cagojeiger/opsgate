# 데이터 리텐션 정책

이 문서는 opsgate가 보관하는 감사/이력 데이터의 보관 기준과, 수평 확장
환경에서 리텐션 작업을 안전하게 실행하기 위한 구현 기준을 정의합니다.

현재 문서는 **정책/구현 기준**입니다. 실제 삭제 worker가 구현되기 전까지는
런타임 동작을 의미하지 않습니다.

## 목적

opsgate는 개인용 운영 보조 도구지만, 다음 데이터가 계속 쌓입니다.

- MCP/REST 호출 이력
- SQL query 실행 이력
- credential 변경 이력
- 인증/도구/정책 거부 감사 로그

리텐션 정책의 목적은 다음과 같습니다.

1. 데이터베이스가 무제한 커지는 것을 막습니다.
2. 보안/운영 감사에 필요한 기간은 유지합니다.
3. active credential과 사용자 identity는 실수로 삭제하지 않습니다.
4. 수평 확장 시 여러 api replica가 동시에 cleanup을 수행하지 않게 합니다.

## 보관 대상과 기본 기간

| 데이터 | 기본 보관 기간 | 비고 |
|---|---:|---|
| `users` | 무기한 | owner identity. 리텐션 대상 아님 |
| active `credentials` | 무기한 | 현재 설정. 리텐션 대상 아님 |
| deleted `credentials` tombstone | 400일 | `credential_history`보다 길게 보관해 FK 충돌 방지 |
| `credential_history` | 365일 | credential register/update/delete 이력 |
| `audit_logs` | 365일 | 인증, MCP/API, 정책 거부, 시스템 감사 |
| `api_call_history` | 90일 | HTTP target 호출 이력. 많이 쌓일 수 있음 |
| `sql_query_history` | 90일 | SQL 실행 이력. 많이 쌓일 수 있음 |

삭제된 credential tombstone 보관 기간은 `credential_history` 보관 기간보다
짧으면 안 됩니다. 현재 schema에서 `credential_history.credential_id`는
`credentials(id)`를 참조하므로, tombstone을 먼저 지우면 아직 보관 중인
history row와 충돌할 수 있습니다.

## 비밀 데이터 원칙

리텐션은 비밀을 오래 보관하기 위한 정책이 아닙니다.

- credential 삭제 시 `secret_ciphertext`는 즉시 제거되어야 합니다.
- `secret_destroyed_at`은 secret 제거 시점을 기록합니다.
- audit/history에는 Bearer token, OAuth code, PKCE verifier, Authorization header,
  SQL params, HTTP body, target secret 값을 저장하지 않습니다.
- 리텐션 로그에는 삭제 row count만 기록합니다.

허용되는 리텐션 로그 예:

```text
retention cleanup completed api_call_history_deleted=1200 sql_query_history_deleted=830 audit_logs_deleted=4
```

금지되는 리텐션 로그 예:

```text
query=...
params=...
credential_alias=...
database_url=...
secret=...
```

## 수평 확장 실행 원칙

opsgate는 docker compose에서도 기본 api replica를 2개로 실행할 수 있고, 운영에서도
여러 pod/instance로 수평 확장될 수 있습니다. 따라서 리텐션 worker는 다음 원칙을
따라야 합니다.

```text
여러 api replica가 worker loop를 띄워도,
실제로 cleanup DELETE를 수행하는 worker는 한 번에 하나뿐이어야 한다.
```

이를 위해 Postgres advisory lock을 사용합니다.

```text
api-1 ─┐
api-2 ─┼─> pg_try_advisory_lock('opsgate.retention')
api-3 ─┘

lock 획득 성공: cleanup 실행
lock 획득 실패: 이번 회차 skip
```

### Lock 방식

권장 방식은 session-level advisory lock입니다.

- `pg_try_advisory_lock(...)`으로 획득합니다.
- cleanup 실행 동안 전용 connection을 유지합니다.
- cleanup 완료 후 `pg_advisory_unlock(...)`으로 해제합니다.
- 프로세스가 죽거나 connection이 끊기면 Postgres가 lock을 자동 해제합니다.

transaction-level lock(`pg_try_advisory_xact_lock`)은 cleanup 전체를 하나의 긴
transaction으로 묶도록 유도할 수 있으므로 기본 방식으로 사용하지 않습니다.

## 삭제 방식

대량 DELETE는 반드시 batch 단위로 수행합니다.

예시:

```sql
WITH doomed AS (
    SELECT id
    FROM api_call_history
    WHERE created_at < $1
    ORDER BY created_at
    LIMIT $2
)
DELETE FROM api_call_history h
USING doomed
WHERE h.id = doomed.id;
```

각 테이블은 다음 방식으로 반복합니다.

```text
1. cutoff 이전 row를 batch_size만큼 삭제
2. 삭제 row count 기록
3. 0건이면 해당 테이블 종료
4. 다음 테이블 진행
```

하나의 거대한 transaction으로 모든 테이블을 삭제하지 않습니다.

## 권한 원칙

리텐션 worker는 DELETE 권한을 필요로 합니다. runtime 계정인 `opsgate_app`에
광범위한 DELETE 권한을 추가하지 않는 것이 원칙입니다.

권장 구성:

```env
OPSGATE_DATABASE_URL=postgres://opsgate_app:...@postgres:5432/opsgate
OPSGATE_DATABASE_MIGRATE_URL=postgres://opsgate_owner:...@postgres:5432/opsgate
OPSGATE_RETENTION_DATABASE_URL=postgres://opsgate_retention:...@postgres:5432/opsgate
```

`opsgate_retention` role은 다음 범위의 권한만 가져야 합니다.

- advisory lock 실행
- retention 대상 테이블의 제한된 DELETE
- readiness 확인을 위한 최소 SELECT

초기 구현에서 별도 role을 도입하지 못한다면, 그 결정은 명시적으로 기록하고
나중에 별도 role로 분리해야 합니다.

## 설정 기준

초기 기본값은 다음을 기준으로 합니다.

```env
OPSGATE_RETENTION_ENABLED=false
OPSGATE_RETENTION_RUN_INTERVAL_HOURS=24
OPSGATE_RETENTION_BATCH_SIZE=1000

OPSGATE_RETENTION_AUDIT_LOG_DAYS=365
OPSGATE_RETENTION_API_CALL_HISTORY_DAYS=90
OPSGATE_RETENTION_SQL_QUERY_HISTORY_DAYS=90
OPSGATE_RETENTION_CREDENTIAL_HISTORY_DAYS=365
OPSGATE_RETENTION_DELETED_CREDENTIAL_DAYS=400
```

기본값은 `enabled=false`입니다. 리텐션은 삭제 작업이므로, 최초 구현에서는 명시적으로
켠 환경에서만 실행합니다.

설정 검증 규칙:

- 모든 day 값은 1 이상이어야 합니다.
- batch size는 1 이상이어야 합니다.
- `deleted_credential_days >= credential_history_days`이어야 합니다.
- interval은 너무 짧게 설정하지 않습니다. 로컬 테스트 외에는 1시간 이상을 권장합니다.

## Worker 실행 흐름

```text
server boot
  │
  ├─ migrations 실행
  ├─ runtime DB pool 생성
  ├─ retention enabled 확인
  │   └─ enabled=true면 retention worker spawn
  └─ HTTP/MCP server 시작
```

worker loop:

```text
loop every interval
  │
  ├─ startup/interval jitter 적용
  ├─ retention DB connection 획득
  ├─ pg_try_advisory_lock
  │   ├─ false: skip log 후 종료
  │   └─ true: cleanup 실행
  ├─ table별 batch delete
  ├─ count-only structured log 기록
  └─ unlock
```

## 검증 기준

단위/통합 테스트:

- cutoff 이전 row만 삭제합니다.
- cutoff 이후 row는 보존합니다.
- batch size보다 많은 row는 여러 batch로 삭제합니다.
- 삭제 대상이 없으면 0 count를 반환합니다.
- `deleted_credential_days < credential_history_days` 설정은 거부합니다.
- advisory lock은 두 connection 중 하나만 획득할 수 있습니다.

로컬 수평 확장 smoke:

```bash
docker compose up -d --build
```

기본 compose는 api replica 2개와 nginx proxy를 사용합니다. 리텐션 worker 구현 후에는
다음 조건을 확인합니다.

```text
api-1, api-2 둘 다 worker loop는 시작할 수 있음
하지만 같은 회차에서 cleanup completed는 하나의 replica에서만 발생해야 함
다른 replica는 lock busy/skip이어야 함
```

## 보류 항목

다음 기능은 초기 리텐션 구현 범위에 포함하지 않습니다.

- archive/export
- table partitioning
- UI에서 retention 수동 실행
- MCP tool로 retention 실행
- per-user retention override

필요해지면 별도 설계 문서에서 다룹니다.
