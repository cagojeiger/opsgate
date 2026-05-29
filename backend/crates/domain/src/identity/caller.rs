use serde::{Deserialize, Serialize};

use crate::User;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Browser,
    Api,
    Mcp,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Caller {
    pub user: User,
    pub channel: Channel,
}
