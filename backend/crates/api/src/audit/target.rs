#[derive(Debug, Clone)]
pub(crate) struct AuditTarget {
    target_type: String,
    target_id: Option<String>,
    target_key: Option<String>,
}

impl AuditTarget {
    pub(crate) fn identity(id: Option<String>, sub: Option<String>) -> Self {
        Self {
            target_type: "identity".to_owned(),
            target_id: id,
            target_key: sub,
        }
    }

    pub(crate) fn route(route_or_path: impl Into<String>) -> Self {
        Self {
            target_type: "route".to_owned(),
            target_id: None,
            target_key: Some(route_or_path.into()),
        }
    }

    pub(crate) fn tool(tool: impl Into<String>) -> Self {
        Self {
            target_type: "tool".to_owned(),
            target_id: None,
            target_key: Some(tool.into()),
        }
    }

    pub(crate) fn credential(id: Option<String>, alias: impl Into<String>) -> Self {
        Self {
            target_type: "credential".to_owned(),
            target_id: id,
            target_key: Some(alias.into()),
        }
    }

    pub(crate) fn into_parts(self) -> (Option<String>, Option<String>, Option<String>) {
        (Some(self.target_type), self.target_id, self.target_key)
    }
}
