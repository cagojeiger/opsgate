# `sql.query`

서피스:

```text
/mcp
```

목적: `category=sql`, `provider=postgres` 자격 증명을 통해 읽기 전용 SQL
쿼리를 실행하고, 결과를 LLM이 읽기 쉬운 column-oriented JSON으로 반환한다.

테이블이나 컬럼 이름을 모를 때는 먼저 [`sql.schema`](sql-schema.md)를 사용한다.
`sql.schema`는 구조만 반환하고, `sql.query`는 실제 행 값을 반환한다.

입력:

```json
{
  "alias": "analytics-db",
  "purpose": "Count failed payments from yesterday",
  "query": "select status, count(*) as total from payments where created_at >= $1 group by status",
  "params": ["2026-05-19"],
  "jsonpath": ["$.status", "$.total"],
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
- `jsonpath`
- `max_rows`
- `max_bytes`
- `timeout_ms`

## 출력 형태

`sql.query`는 행 배열을 그대로 반환하지 않고, 기본적으로 컬럼별 배열로
전치(transpose)해서 `body`에 담는다.

예를 들어 DB 결과가 다음과 같다면:

```text
status | total
-------+------
failed | 42
paid   | 900
```

응답은 다음과 같다.

```json
{
  "body": {
    "status": ["failed", "paid"],
    "total": [42, 900]
  },
  "row_count": 2,
  "truncated": false,
  "original_bytes": 45,
  "returned_bytes": 45,
  "latency_ms": 4
}
```

`row_count`는 `max_rows` 적용 뒤 Postgres에서 가져온 행 수다. `jsonpath`나
`max_bytes`로 `body`가 줄어들거나 `null`이 되어도, 이 값은 원본 SQL 결과의
행 수를 의미한다.

## JSONPath projection

큰 결과나 특정 컬럼만 필요할 때는 `jsonpath`를 사용한다. JSONPath는 전치된
`body`에 적용된다.

입력:

```json
{
  "alias": "analytics-db",
  "purpose": "Read payment statuses only",
  "query": "select status, count(*) as total from payments group by status",
  "jsonpath": ["$.status"]
}
```

출력:

```json
{
  "body": {
    "$.status": [["failed", "paid"]]
  },
  "row_count": 2,
  "truncated": false,
  "original_bytes": 45,
  "returned_bytes": 32,
  "latency_ms": 4
}
```

JSONPath projection 결과는 `api.call`과 같은 공통 JSON 출력 규칙을 따른다.
각 path는 결과 객체의 key가 되고, 일반 selection은 매칭된 node 목록이 배열로
들어간다. 개수만 필요하면 `.length()` 또는 `.count()` suffix를 사용해 작은 숫자만
반환할 수 있다. 예: `$.status.length()` 또는 `$.status.count()`.

## Truncation

`body`가 `max_bytes`를 넘으면 partial JSON을 반환하지 않는다. 대신 `body`는
`null`이 되고, 다음 호출을 좁히기 위한 `more`가 붙는다.

```json
{
  "body": null,
  "row_count": 100,
  "truncated": true,
  "original_bytes": 287000,
  "returned_bytes": 0,
  "latency_ms": 34,
  "more": {
    "truncated": true,
    "options": {
      "preferred_next": "jsonpath",
      "suggested_jsonpath": ["$.id", "$.status"],
      "suggested_max_bytes": 8192
    },
    "hints": ["response JSON is too large; retry with jsonpath using 1-3 paths from suggested_jsonpath or preview.paths"]
  }
}
```

`truncated=true`는 두 경우 모두 가능하다.

- SQL 행 수가 `max_rows`를 넘어 잘림
- JSON 출력이 `max_bytes`를 넘어 `body=null`로 대체됨

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
- policy/parser 거부 이력은 raw SQL 조각을 남기지 않도록 generic safe message만 저장한다.
- params 값은 저장되지 않는다.
- 결과 행과 결과 값은 저장되지 않는다.
- DB 엔드포인트는 저장되지 않는다.
- 시크릿은 저장되지 않는다.
- 쿼리 상관관계는 `query_sha256`로 추적한다.
- 반환 원본 컬럼 이름은 `result_columns`로 저장되며, 결과 값은 저장되지 않는다.

LLM 가이드:

- `count(*)`, 그룹 요약, 정확한 조회 조건(predicate), 명시적 컬럼 목록으로 시작한다.
- 테이블이 작다고 확신하지 않는 한 `select *`는 피한다.
- 결과는 컬럼별 배열이므로, 행 단위 객체가 필요하면 필요한 컬럼을 명시하고 같은
  인덱스의 값들을 하나의 행으로 해석한다.
- 특정 컬럼이나 큰 결과의 일부만 필요하면 `jsonpath`를 사용한다. 개수만 필요하면
  전체 배열을 받지 말고 `.length()`/`.count()`를 사용한다.
- `body=null`이고 `more.options.preferred_next=jsonpath`이면 `max_bytes`부터
  올리지 말고 `suggested_jsonpath` 또는 `more.preview.paths`로 먼저 좁힌다.
