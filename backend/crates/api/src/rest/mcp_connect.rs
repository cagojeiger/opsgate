use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/mcp/connect", get(connect))
}

async fn connect(State(state): State<AppState>) -> Json<McpConnectResponse> {
    Json(McpConnectResponse::from_public_url(
        &state.config.opsgate_public_url,
    ))
}

#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub(crate) struct McpConnectResponse {
    pub(crate) runtime_url: String,
    pub(crate) admin_url: String,
    pub(crate) recommended_url: String,
    pub(crate) runtime_tools: Vec<String>,
    pub(crate) admin_tools: Vec<String>,
    pub(crate) notes: Vec<String>,
}

impl McpConnectResponse {
    fn from_public_url(public_url: &str) -> Self {
        let base = public_url.trim_end_matches('/');
        let runtime_url = format!("{base}/mcp");
        let admin_url = format!("{base}/mcp/admin");
        Self {
            recommended_url: runtime_url.clone(),
            runtime_url,
            admin_url,
            runtime_tools: [
                "me",
                "credential.list",
                "api.call",
                "sql.schema",
                "sql.query",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            admin_tools: [
                "credential.register_http",
                "credential.register_sql",
                "credential.update_http",
                "credential.update_sql",
                "credential.delete",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            notes: vec![
                "Claude에는 기본적으로 runtime_url을 연결하세요.".to_owned(),
                "admin_url은 credential 관리가 필요할 때만 사용하세요.".to_owned(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_urls_from_public_url() {
        let out = McpConnectResponse::from_public_url("https://opsgate.example.test/");
        assert_eq!(out.runtime_url, "https://opsgate.example.test/mcp");
        assert_eq!(out.admin_url, "https://opsgate.example.test/mcp/admin");
        assert_eq!(out.recommended_url, out.runtime_url);
    }
}
