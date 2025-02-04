use crate::api::{
    ApiResult,
    error::{
        MismatchedSignature, UnsupportedMediaType, UnsupportedUserAgent, UnsupportedWebhookEvent,
    },
    header_get_required,
};

use axum::{Json, Router, body::Bytes, http::HeaderMap, routing::post};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct User {
    id: i64,
    username: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Organization {
    id: i64,
    username: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Team {
    id: i64,
    slug: String,
    name: String,
    privacy: String,
    permission: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Commit {
    distinct: Option<bool>,
    id: String,
    message: String,
    timestamp: String,
    tree_id: Option<String>,
    url: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Repository {
    name: String,
    full_name: String,
    owner: User,
    description: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Pusher {
    name: String,
    email: Option<String>,
    username: Option<String>,
    date: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Membership {
    action: String,
    member: Option<User>,
    organization: Organization,
    repository: Option<Repository>,
    scope: String,
    sender: Option<User>,
    team: Team,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Push {
    after: String,
    base_ref: Option<String>,
    before: String,
    compare_url: String,
    created: Option<bool>,
    deleted: Option<bool>,
    forced: Option<bool>,
    r#ref: String,
    head_commit: Option<Commit>,
    repository: Repository,
    pusher: User,
    commits: Vec<Commit>,
    sender: Option<User>,
    organization: Option<Organization>,
}

fn hex_digest(secret: &str, bytes: &[u8]) -> ApiResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(bytes);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(""))
}

fn check_content_type(content_type: &str) -> ApiResult<()> {
    if content_type == "application/json" {
        Ok(())
    } else {
        Err(UnsupportedMediaType::new(content_type.to_string()).into())
    }
}

fn check_user_agent(user_agent: &str) -> ApiResult<()> {
    if user_agent.starts_with("Go-http-client/") {
        Ok(())
    } else {
        Err(UnsupportedUserAgent::new(user_agent.to_string()).into())
    }
}

fn check_signature(signature: &str, bytes: &[u8]) -> ApiResult<()> {
    let secret = std::env::var("FORGEJO_WEBHOOK_SECRET")?;
    let expected = hex_digest(&secret, bytes)?;
    if signature == expected {
        Ok(())
    } else {
        Err(MismatchedSignature::new(signature.to_string()).into())
    }
}

async fn webhook_handler(headers: HeaderMap, bytes: Bytes) -> ApiResult<()> {
    let content_type = header_get_required(&headers, "content-type")?;
    let event = header_get_required(&headers, "x-forgejo-event")?;
    let _delivery = header_get_required(&headers, "x-forgejo-delivery")?;
    let signature = header_get_required(&headers, "x-forgejo-signature")?;
    let user_agent = header_get_required(&headers, "user-agent")?;

    check_content_type(content_type)?;
    check_user_agent(user_agent)?;
    check_signature(signature, &bytes)?;

    match event {
        "push" => {
            let Json(_push): Json<Push> = Json::from_bytes(&bytes)?;
        }
        "membership" => {
            let Json(_membership): Json<Membership> = Json::from_bytes(&bytes)?;
        }
        _ => return Err(UnsupportedWebhookEvent::new(event.to_string()).into()),
    }

    Ok(())
}

pub fn routes() -> Router {
    Router::new().route("/webhook", post(webhook_handler))
}
