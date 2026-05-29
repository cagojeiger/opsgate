use serde::{Deserialize, Serialize};

use crate::{Role, User};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Browser,
    Api,
    Mcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Caller {
    pub user: User,
    pub channel: Channel,
    pub role: Role,
    pub request_id: Option<String>,
    pub remote_ip: Option<String>,
    pub user_agent: Option<String>,
}

impl Caller {
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    pub fn with_request_metadata(
        mut self,
        request_id: Option<String>,
        remote_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        self.request_id = request_id;
        self.remote_ip = remote_ip;
        self.user_agent = user_agent;
        self
    }
}
