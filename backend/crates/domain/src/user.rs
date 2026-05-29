//! The canonical identity `User` entity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn can_execute(self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub sub: String,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
