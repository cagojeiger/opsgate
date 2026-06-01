# `sql.schema`

서피스:

```text
/mcp
```

목적: 행 값을 반환하지 않고 `category=sql` 자격 증명의 데이터베이스 구조를 조회한다.

테이블이나 컬럼 이름을 모를 때 `sql.query`보다 먼저 사용한다.

입력:

```json
{
  "alias": "analytics-db",
  "purpose": "Find tables needed for API call history analysis",
  "mode": "tables",
  "limit": 50,
  "cursor": "",
  "max_bytes": 65536,
  "timeout_ms": 3000
}
```

테이블 상세:

```json
{
  "alias": "analytics-db",
  "purpose": "Inspect columns for API call history aggregation",
  "mode": "table",
  "table": "api_call_history",
  "namespace": "public",
  "include_indexes": true
}
```

필수:

- `alias`
- `purpose`

기본값:

- `mode=tables`
- `limit=50`
- `max_bytes=65536`
- `timeout_ms=3000`
- `mode=table`일 때 `namespace=public`
- `include_indexes=false`

출력:

```json
{
  "mode": "tables",
  "tables": [
    {"namespace": "public", "name": "audit_logs", "kind": "table"},
    {"namespace": "public", "name": "api_call_history", "kind": "table"}
  ],
  "page": {
    "limit": 50,
    "returned": 2,
    "has_more": false
  },
  "truncated": false,
  "returned_bytes": 180,
  "latency_ms": 4
}
```

테이블 상세 출력:

```json
{
  "mode": "table",
  "table": {
    "namespace": "public",
    "name": "api_call_history",
    "kind": "table",
    "columns": [
      {"name": "id", "type": "bigint", "nullable": false},
      {"name": "created_at", "type": "timestamp with time zone", "nullable": false},
      {"name": "outcome", "type": "text", "nullable": false}
    ],
    "primary_key": ["id"]
  },
  "truncated": false,
  "returned_bytes": 420,
  "latency_ms": 5
}
```

규칙:

- 자격 증명은 `category=sql`, `provider=postgres`여야 한다.
- 시크릿과 엔드포인트는 절대 반환되지 않는다.
- 행 값은 절대 반환되지 않는다.
- 쿼리 텍스트는 호출자로부터 받지 않는다.
- 이 툴은 좁은 범위의 내부 메타데이터 조회만 수행하며 고정된 JSON 봉투(envelope)를
  반환한다.
- `sql.schema`는 `sql.query`가 `allow_metadata`를 통해 원시 메타데이터 SQL을
  허용하지 않더라도 테이블/컬럼 구조를 조회할 수 있다.
- `include_indexes`는 인덱스 메타데이터가 출력 크기를 키울 수 있어
  옵트인(opt-in) 방식이다.

LLM 가이드:

- 테이블 이름을 모를 때는 `mode=tables`를 먼저 사용한다.
- 익숙하지 않은 테이블에 `sql.query`를 작성하기 전에 `mode=table`을 사용한다.
- 원시 `information_schema` 쿼리보다 `sql.schema`를 선호한다.
- 구체적인 테이블과 컬럼을 선택한 뒤에만 `sql.query`를 사용한다.
