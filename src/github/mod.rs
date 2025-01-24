use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, Method, StatusCode},
    routing::post,
};
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

fn hex_digest(secret: &str, bytes: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(bytes);
    let bytes = mac.finalize().into_bytes();
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

fn signature_matches(signature: &str, bytes: &[u8]) -> bool {
    let secret = std::env::var("GITHUB_WEBHOOK_SECRET").unwrap();
    let expected = format!("sha256={}", hex_digest(&secret, bytes));
    signature == expected
}

async fn webhook(method: Method, headers: HeaderMap, bytes: Bytes) -> StatusCode {
    if method != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED;
    }

    macro_rules! header {
        ($literal:literal) => {
            match headers.get($literal) {
                Some(val) => match val.to_str() {
                    Ok(s) => s,
                    Err(_) => return StatusCode::BAD_REQUEST,
                },
                None => return StatusCode::BAD_REQUEST,
            }
        };
    }
    let content_type = header!("content-type");
    let _hook_id = header!("x-github-hook-id");
    let event = header!("x-github-event");
    let _delivery = header!("x-github-delivery");
    let _signature = header!("x-hub-signature");
    let signature_256 = header!("x-hub-signature-256");
    let user_agent = header!("user-agent");
    let _installation_target_type = header!("x-github-hook-installation-target-type");
    let _installation_target_id = header!("x-github-hook-installation-target-id");

    if content_type != "application/json" {
        return StatusCode::BAD_REQUEST;
    }
    if !user_agent.starts_with("GitHub-Hookshot/") {
        return StatusCode::BAD_REQUEST;
    }
    if !signature_matches(signature_256, &bytes) {
        return StatusCode::BAD_REQUEST;
    }
    match event {
        "push" => {
            let Json(_push): Json<Push> = match Json::from_bytes(&bytes) {
                Ok(json) => json,
                Err(_) => return StatusCode::BAD_REQUEST,
            };
        }
        "membership" => {
            let Json(_membership): Json<Membership> = match Json::from_bytes(&bytes) {
                Ok(json) => json,
                Err(_) => return StatusCode::BAD_REQUEST,
            };
        }
        _ => (),
    }

    StatusCode::OK
}

pub fn routes() -> Router {
    Router::new().route("/webhook", post(webhook))
}
