# `credential.delete`

서피스:

```text
/mcp/admin
```

목적: 자격 증명을 소프트 삭제하고 봉인된 시크릿을 크립토슈레드(cryptoshred)한다.

입력:

```json
{
  "alias": "old-prod-k8s",
  "reason": "Retire obsolete cluster credential after replacement"
}
```

필수:

- `alias`
- `reason`

출력:

```json
{
  "alias": "old-prod-k8s",
  "deleted": true
}
```

규칙:

- admin 전용이다.
- 사용자가 명시적으로 확인한 뒤에만 호출한다.
- 삭제된 자격 증명은 `credential.list`에서 더 이상 보이지 않는다.
- 삭제된 자격 증명은 `api.call`이나 `sql.query`로 사용할 수 없다.
- 메타데이터와 이력은 그대로 남는다.
- 시크릿 자료는 `secret_ciphertext=NULL`로 설정하여 파기한다.
- `secret_destroyed_at`이 기록된다.
- alias 변경은 삭제 후 재등록으로 처리한다.

감사/이력:

- 감사 액션: `mcp.credential.delete`
- 이력 액션: `delete`
- 상세(detail)에 `delete_reason`이 포함된다.
