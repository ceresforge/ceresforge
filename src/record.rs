use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::OffsetDateTime;

#[allow(dead_code)]
#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SamlRequestedAttribute {
    pub friendly_name: String,
    pub name: String,
    pub name_format: String,
    pub is_required: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SamlAttribute {
    pub friendly_name: String,
    pub name: String,
    pub name_format: String,
    pub value: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SamlProvider {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub metadata_url: String,
    pub sso_url: String,
    pub certificate: String,
    pub requested_attributes: JsonValue,
    pub mapped_attributes: JsonValue,
    pub is_user_creation_allowed: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SamlCredentials {
    pub id: i64,
    pub user_id: i64,
    pub provider_id: i64,
    pub name_id: String,
    pub attributes: JsonValue,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
