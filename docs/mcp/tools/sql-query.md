# `sql.query`

서피스:

```text
/mcp
```

목적: `category=sql` 자격 증명을 통해 읽기 전용 SQL 쿼리를 실행한다.

테이블이나 컬럼 이름을 모를 때는 먼저 [`sql.schema`](sql-schema.md)를 사용한다.
`sql.schema`는 구조만 반환하고, `sql.query`는 실제 행 값을 반환한다.

입력:

```json
{
  "alias": "analytics-db",
  "purpose": "Count failed payments from yesterday",
  "query": "select status, count(*) from payments where created_at >= $1 group by status",
  "params": ["2026-05-19"],
  "shape": "rows",
  "max_rows": 100,
  "max_bytes": 65536,
  "timeout_ms": 3000
}
```

필수:

- `alias`
- `purpose`
- `query`

선택:

- `params`
- `shape`
- `max_rows`
- `max_bytes`
- `timeout_ms`

출력 형태(shape):

`shape=rows`:

```json
{
  "columns": [{"name": "status", "type": "text"}],
  "rows": [{"status": "failed", "count": 42}],
  "row_count": 1,
  "truncated": false,
  "returned_bytes": 32,
  "latency_ms": 4
}
```

`shape=columns`:

```json
{
  "columns": [{"name": "status", "type": "text"}],
  "shape": "columns",
  "data": {"status": ["failed", "paid"], "count": [42, 900]},
  "row_count": 2,
  "truncated": false,
  "returned_bytes": 44,
  "latency_ms": 4
}
```

`shape=values`:

```json
{
  "columns": [{"name": "status", "type": "text"}],
  "shape": "values",
  "column": {"name": "status", "type": "text"},
  "values": ["failed", "paid"],
  "row_count": 2,
  "truncated": false,
  "returned_bytes": 18,
  "latency_ms": 4
}
```

규칙:

- 자격 증명은 `category=sql`, `provider=postgres`여야 한다.
- alias는 존재하지만 다른 category나 provider에 속한 경우, 쿼리는
  `wrong_credential_provider`로 거부된다. 감사/이력에는 자격 증명 메타데이터
  스냅샷만 남으며, 시크릿·쿼리·params·결과 값은 절대 저장되지 않는다.
- 문장은 AST로 검증된 단일 `SELECT` 또는 `WITH`여야 한다.
- `EXPLAIN`은 `allow_explain=true`가 필요하다.
- `EXPLAIN ANALYZE`는 `allow_explain=true`와
  `allow_explain_analyze=true`가 모두 필요하다.
- 쓰기는 거부된다.
- 잠금(locking) 절은 거부된다.
- 내장 차단 함수는 거부된다.
- `denied_functions`에 포함된 함수는 거부된다.
- `denied_functions`에 포함된 SQL value 함수 이름도 거부된다.
- opsgate에는 일반적인 스키마 화이트리스트 정책이 없다. 데이터베이스 엔드포인트와
  DB 역할(role) 권한이 데이터 경계를 정의한다.
- Postgres 메타데이터 스키마(`pg_catalog`, `information_schema`)에는
  `allow_metadata=true`가 필요하다.
- 실행은 Postgres 읽기 전용 트랜잭션 내부에서 이루어진다.

이력/감사 안전성:

- 쿼리 텍스트는 저장되지 않는다.
- params 값은 저장되지 않는다.
- 결과 행은 저장되지 않는다.
- DB 엔드포인트는 저장되지 않는다.
- 시크릿은 저장되지 않는다.
- 쿼리 상관관계는 `query_sha256`로 추적한다.
- 반환된 컬럼 이름은 `result_columns`로 저장되며, 결과 값은
  저장되지 않는다.

LLM 가이드:

- `count(*)`, 그룹 요약, 정확한 조회 조건(predicate), 명시적 컬럼 목록으로 시작한다.
- 테이블이 작다고 확신하지 않는 한 `select *`는 피한다.
- 행 단위 의미가 필요하면 `shape=rows`가 가장 적합하다.
- `shape=columns`는 여러 행을 비교할 때 키 반복을 줄여준다.
- `shape=values`는 단일 컬럼만 선택할 때 사용한다.
- 잘렸다면(truncated) `more.options`와 `more.hints`를 활용한다.
