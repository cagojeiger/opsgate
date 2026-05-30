use axum::http::request::Parts;
use opsgate_domain::Caller;
use rmcp::ErrorData;
use rmcp::Json;
use schemars::JsonSchema;
use serde::Serialize;

use crate::credential::CredentialSummary;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpToolset {
    Runtime,
    Admin,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct McpMeOutput {
    pub service: ServiceInfo,
    pub capabilities: Vec<Capability>,
    pub credential_summary: CredentialSummary,
    pub id: String,
    pub sub: String,
    pub email: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub purpose: String,
    pub secret_model: String,
    pub workflow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct Capability {
    pub tool: String,
    pub description: String,
}

pub async fn call(
    state: &AppState,
    parts: &Parts,
    toolset: McpToolset,
) -> Result<Json<McpMeOutput>, ErrorData> {
    let caller = parts
        .extensions
        .get::<Caller>()
        .ok_or_else(|| ErrorData::invalid_params("authenticated caller extension missing", None))?;
    let summary = state
        .credentials
        .summary(caller.user.id)
        .await
        .map_err(map_error)?;
    Ok(Json(build_me(caller, toolset, summary)))
}

fn build_me(caller: &Caller, toolset: McpToolset, summary: CredentialSummary) -> McpMeOutput {
    McpMeOutput {
        service: ServiceInfo {
            name: "opsgate".to_owned(),
            purpose: "Policy-gated HTTP/SQL broker for LLM clients.".to_owned(),
            secret_model: "Secrets and endpoints are hidden from MCP clients; secret values are sealed at rest and never returned.".to_owned(),
            workflow: workflow_for_toolset(toolset),
        },
        capabilities: capabilities_for_toolset(toolset),
        credential_summary: summary,
        id: caller.user.id.to_string(),
        sub: caller.user.sub.clone(),
        email: caller.user.email.clone(),
        name: caller.user.display_name.clone(),
    }
}

fn capabilities_for_toolset(toolset: McpToolset) -> Vec<Capability> {
    let specs = match toolset {
        McpToolset::Runtime => vec![
            (
                "credential.list",
                "등록된 credential의 alias, metadata, policy를 조회합니다.",
            ),
            ("api.call", "HTTP credential alias로 JSON API를 호출합니다."),
            (
                "sql.schema",
                "SQL credential alias로 Postgres schema metadata를 조회합니다.",
            ),
            (
                "sql.query",
                "SQL credential alias로 읽기 전용 Postgres 쿼리를 실행합니다.",
            ),
        ],
        McpToolset::Admin => vec![
            (
                "credential.list",
                "등록된 credential의 alias, metadata, policy를 조회합니다.",
            ),
            (
                "credential.register_http",
                "HTTPS API credential을 등록하고 secret header를 봉인합니다.",
            ),
            (
                "credential.register_sql",
                "Postgres credential을 등록하고 username/password를 봉인합니다.",
            ),
            (
                "credential.update_http",
                "HTTP credential의 metadata와 policy를 수정합니다.",
            ),
            (
                "credential.update_sql",
                "SQL credential의 metadata와 policy를 수정합니다.",
            ),
            (
                "credential.delete",
                "credential을 소프트 삭제하고 봉인된 secret을 파기합니다.",
            ),
        ],
    };
    specs
        .into_iter()
        .map(|(tool, description)| Capability {
            tool: tool.to_owned(),
            description: description.to_owned(),
        })
        .collect()
}

fn workflow_for_toolset(toolset: McpToolset) -> Vec<String> {
    match toolset {
        McpToolset::Runtime => vec![
            "me로 capability와 credential_summary를 확인합니다.".to_owned(),
            "credential.list로 alias와 policy를 확인합니다.".to_owned(),
            "credential category에 맞는 runtime 도구를 호출합니다.".to_owned(),
        ],
        McpToolset::Admin => vec![
            "me로 관리 capability와 credential_summary를 확인합니다.".to_owned(),
            "credential.register_*로 secret을 봉인해 등록합니다.".to_owned(),
            "credential.update_*로 metadata와 policy만 수정합니다.".to_owned(),
            "secret 교체나 endpoint 변경은 credential.delete 후 재등록합니다.".to_owned(),
        ],
    }
}

fn map_error(error: opsgate_core::Error) -> ErrorData {
    match error {
        opsgate_core::Error::Forbidden(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::Validation(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::NotFound(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::Internal(message) => {
            tracing::error!(event = "mcp.me.internal_error", detail = %message);
            ErrorData::internal_error("internal server error", None)
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_domain::{Caller, Channel, User};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    use super::{McpToolset, build_me};
    use crate::credential::CredentialSummary;

    #[test]
    fn admin_me_reports_admin_capabilities_without_aliases() {
        let now = Utc::now();
        let user = User {
            id: Uuid::nil(),
            sub: "sub-1".to_owned(),
            email: "user@example.test".to_owned(),
            display_name: "Test User".to_owned(),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let out = build_me(
            &Caller {
                user,
                channel: Channel::Mcp,
                request_id: None,
                remote_ip: None,
                user_agent: None,
            },
            McpToolset::Admin,
            CredentialSummary {
                total: 0,
                by_category: BTreeMap::new(),
                by_provider: BTreeMap::new(),
                tags: BTreeMap::new(),
            },
        );
        assert!(
            out.capabilities
                .iter()
                .any(|capability| capability.tool == "credential.delete")
        );
        assert_eq!(out.id, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn runtime_me_excludes_admin_capabilities_and_aliases() -> Result<(), serde_json::Error> {
        let now = Utc::now();
        let user = User {
            id: Uuid::nil(),
            sub: "sub-1".to_owned(),
            email: "user@example.test".to_owned(),
            display_name: "Test User".to_owned(),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let mut by_provider = BTreeMap::new();
        by_provider.insert("k8s".to_owned(), 1);
        let out = build_me(
            &Caller {
                user,
                channel: Channel::Mcp,
                request_id: None,
                remote_ip: None,
                user_agent: None,
            },
            McpToolset::Runtime,
            CredentialSummary {
                total: 1,
                by_category: BTreeMap::new(),
                by_provider,
                tags: BTreeMap::new(),
            },
        );
        let json = serde_json::to_string(&out)?;

        assert!(
            out.capabilities
                .iter()
                .all(|capability| capability.tool != "credential.delete")
        );
        assert!(!json.contains("prod-api"));
        Ok(())
    }
}
