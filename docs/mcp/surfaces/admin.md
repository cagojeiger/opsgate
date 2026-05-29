# `/mcp/admin` admin 서피스

목적: 자격 증명 라이프사이클 관리.

툴:

```text
me
credential.register_http
credential.register_sql
credential.update_http
credential.update_sql
credential.list
credential.delete
```

admin이 자격 증명을 등록하거나, 메타데이터/정책을 조정하거나, 카탈로그
메타데이터를 조회하거나, 자격 증명을 삭제하려고 명시적으로 요청할 때 이 서피스를
사용한다.

규칙:

- 인증된 admin 호출자가 필요하다.
- 대상 실행(target execution) 툴은 여기에 마운트되지 않는다.
- `api.call`과 `sql.query`는 런타임 `/mcp`를 사용한다.
- `credential.update_*`는 시크릿이나 엔드포인트를 변경할 수 없다.
- 시크릿 교체와 대상 변경은 삭제 후 재등록으로 표현된다.

전형적인 흐름:

```text
me
credential.register_http or credential.register_sql
credential.list
credential.update_http or credential.update_sql
credential.delete
```
