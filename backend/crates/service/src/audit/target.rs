#[derive(Debug, Clone)]
pub struct AuditTarget {
    target_type: String,
    target_id: Option<String>,
    target_key: Option<String>,
}

impl AuditTarget {
    pub fn credential(id: Option<String>, alias: impl Into<String>) -> Self {
        Self {
            target_type: "credential".to_owned(),
            target_id: id,
            target_key: Some(alias.into()),
        }
    }

    pub fn into_parts(self) -> (Option<String>, Option<String>, Option<String>) {
        (Some(self.target_type), self.target_id, self.target_key)
    }
}
