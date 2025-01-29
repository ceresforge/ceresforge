use crate::api::{
    Result,
    error::{MismatchedSignature, UnsupportedMediaType, UnsupportedUserAgent},
    header_get_required,
};

use axum::{Json, Router, body::Bytes, http::HeaderMap, routing::post};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Bot {
    id: i64,
    login: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct User {
    id: i64,
    login: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Organization {
    id: i64,
    login: String,
    description: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Owner {
    User(User),
    Organization(Organization),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Sender {
    Bot(Bot),
    User(User),
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
    distinct: bool,
    id: String,
    message: String,
    timestamp: String,
    tree_id: String,
    url: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Repository {
    name: String,
    full_name: String,
    owner: Owner,
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
    sender: Option<Sender>,
    team: Team,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Push {
    after: String,
    base_ref: Option<String>,
    before: String,
    compare: String,
    created: bool,
    deleted: bool,
    forced: bool,
    r#ref: String,
    head_commit: Option<Commit>,
    repository: Repository,
    pusher: Pusher,
    commits: Vec<Commit>,
    sender: Option<Sender>,
    organization: Option<Organization>,
}

fn hex_digest(secret: &str, bytes: &[u8]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(bytes);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(""))
}

fn check_signature(signature: &str, bytes: &[u8]) -> Result<()> {
    let secret = std::env::var("FORGEJO_WEBHOOK_SECRET")?;
    let digest = hex_digest(&secret, bytes)?;
    let expected = format!("sha256={}", digest);
    if signature == expected {
        Ok(())
    } else {
        Err(MismatchedSignature::new(signature.to_string()).into())
    }
}

async fn webhook(headers: HeaderMap, bytes: Bytes) -> Result<()> {
    let content_type = header_get_required(&headers, "content-type")?;
    let _hook_id = header_get_required(&headers, "x-forgejo-hook-id")?;
    let event = header_get_required(&headers, "x-forgejo-event")?;
    let _delivery = header_get_required(&headers, "x-forgejo-delivery")?;
    let _signature = header_get_required(&headers, "x-hub-signature")?;
    let signature_256 = header_get_required(&headers, "x-forgejo-signature-256")?;
    let user_agent = header_get_required(&headers, "user-agent")?;
    let _installation_target_type =
        header_get_required(&headers, "x-forgejo-hook-installation-target-type")?;
    let _installation_target_id =
        header_get_required(&headers, "x-forgejo-hook-installation-target-id")?;

    if content_type != "application/json" {
        return Err(UnsupportedMediaType::new(content_type.to_string()).into());
    }
    if !user_agent.starts_with("GitHub-Hookshot/") {
        return Err(UnsupportedUserAgent::new(user_agent.to_string()).into());
    }

    check_signature(signature_256, &bytes)?;

    match event {
        "push" => {
            let Json(_push): Json<Push> = Json::from_bytes(&bytes)?;
        }
        "membership" => {
            let Json(_membership): Json<Membership> = Json::from_bytes(&bytes)?;
        }
        _ => (),
    }

    Ok(())
}

pub fn routes() -> Router {
    Router::new().route("/webhook", post(webhook))
}
