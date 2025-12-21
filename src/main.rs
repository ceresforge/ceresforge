macro_rules! generate_secure_string {
    ($length:expr) => {{
        use base64ct::{Base64UrlUnpadded, Encoding};
        use rand::RngCore;

        let mut bytes = [0u8; $length];
        rand::rng().fill_bytes(&mut bytes);
        Base64UrlUnpadded::encode_string(&bytes)
    }};
}

mod api;
mod auth;
mod extract;
mod forgejo;
mod frontend;
mod jwt;
mod openid_configuration;
mod record;
mod users;
mod webfinger;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use axum::{
    body::Body, extract::{FromRef, OriginalUri, State}, http::{HeaderMap, StatusCode}, response::{IntoResponse, Response}, routing::get, Router
};
use axum_extra::extract::cookie::Key;
use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use maud::{DOCTYPE, Markup, html};
use reqwest::Client;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::io::{Write, stdin, stdout};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const CSS_PATH: &str = "/ceresforge-0.0.2-dev.2.css";
const SVG_PATH: &str = "/ceresforge-0.0.2-dev.1.svg";

#[derive(Debug, clap::Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    CreateAdmin,
    CreateOauth2Client,
    GenerateCookieKey,
    Migrate,
    MigrateUndo {
        target: i64,
    },
    Server,
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    key: Key,
    jwt_rsa_key: RsaPrivateKey,
    client: Client,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

/*
async fn ws_demo() -> Html<&'static str> {
    Html(include_str!("../frontend/ws-demo.html"))
}

async fn ws_demo_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("../frontend/ws-demo.css"),
    )
}

async fn ws_demo_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript")],
        include_str!("../frontend/ws-demo.js"),
    )
}

async fn css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css"),
            (header::CACHE_CONTROL, "max-age=31536000"),
        ],
        include_str!("../frontend/ceresforge.css"),
    )
}

async fn inter_normal() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "max-age=31536000"),
        ],
        include_bytes!("../frontend/inter-normal-4.1.woff2"),
    )
}

async fn inter_italic() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "max-age=31536000"),
        ],
        include_bytes!("../frontend/inter-italic-4.1.woff2"),
    )
}

async fn svg() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "max-age=31536000"),
        ],
        include_str!("../frontend/ceresforge.svg"),
    )
}
*/

pub fn base(title: &str, description: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                title {
                    (title)
                }
                meta name="color-scheme" content="light dark";
                meta name="description" content=(description);
                meta name="viewport" content="width=device-width, initial-scale=1";
                link rel="icon" href=(SVG_PATH) type="image/svg+xml";
                link rel="stylesheet" href=(CSS_PATH);
            }
            body {
                (body)
            }
        }
    }
}

fn plain_fullscreen(title: &str, description: &str, status_code: StatusCode) -> impl IntoResponse {
    (
        status_code,
        html! {
            (base(title, description, html! {
                div .full-screen {
                    h1 {
                        (title)
                    }
                    p {
                        (description)
                    }
                }
            }))
        },
    )
}

fn plain_400() -> Response {
    plain_fullscreen("400", "Bad Request.", StatusCode::BAD_REQUEST).into_response()
}

fn plain_401() -> Response {
    plain_fullscreen("401", "Unauthorized.", StatusCode::UNAUTHORIZED).into_response()
}

#[allow(dead_code)]
fn plain_403() -> Response {
    plain_fullscreen("403", "Forbidden.", StatusCode::FORBIDDEN).into_response()
}

fn plain_404() -> Response {
    plain_fullscreen("404", "Not Found.", StatusCode::NOT_FOUND).into_response()
}

fn plain_405() -> Response {
    plain_fullscreen("405", "Method Not Allowed.", StatusCode::METHOD_NOT_ALLOWED).into_response()
}

fn plain_500() -> Response {
    plain_fullscreen(
        "500",
        "Internal Server Error.",
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .into_response()
}

async fn method_not_allowed_fallback() -> impl IntoResponse {
    plain_405()
}

#[allow(dead_code)]
async fn fallback() -> impl IntoResponse {
    plain_404()
}

async fn web_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(original_uri): OriginalUri,
) -> impl IntoResponse {
    let frontend_port = match cfg!(debug_assertions) {
        true => 5173,
        false => 3000,
    };
    for (header_name, header_value) in &headers {
        println!("Backend {} {:?}", header_name, header_value);
    }
    let frontend_url = format!("http://localhost:{}{}", frontend_port, original_uri);
    match state.client.get(&frontend_url).send().await {
        Ok(frontend_response) => {
            let mut response_builder = Response::builder().status(frontend_response.status());

            // Copy headers from frontend response to our response
            for (header_name, header_value) in frontend_response.headers() {
                println!("Frontend {} {:?}", header_name, header_value);
                response_builder = response_builder.header(header_name, header_value);
            }

            // Stream the body
            let stream = frontend_response.bytes_stream();
            let body = axum::body::Body::from_stream(stream);

            response_builder.body(body).unwrap_or_else(|e| {
                eprintln!("Error building proxy response: {}", e);
                Response::builder()
                    .status(500)
                    .body(Body::from("Internal Server Error"))
                    .unwrap()
            })
        }
        Err(e) => {
            eprintln!("Error proxying request to frontend: {}", e);
            Response::builder()
                .status(502) // Bad Gateway
                .body(Body::empty())
                .unwrap()
        }
    }
}

async fn app() -> Router {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .max_connections(10)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let cookie_key = std::env::var("COOKIE_KEY").unwrap();

    let key = Key::from(
        Base64UrlUnpadded::decode_vec(&cookie_key)
            .unwrap()
            .as_slice(),
    );

    let jwt_rsa_key_pem = std::env::var("JWT_RSA_KEY").unwrap();
    let jwt_rsa_key_pem = Base64UrlUnpadded::decode_vec(&jwt_rsa_key_pem).unwrap();
    let jwt_rsa_key_pem = String::from_utf8(jwt_rsa_key_pem).unwrap();
    let jwt_rsa_key = RsaPrivateKey::from_pkcs8_pem(&jwt_rsa_key_pem).unwrap();

    let client = Client::new();

    let state = AppState {
        pool,
        key,
        jwt_rsa_key,
        client,
    };

    Router::new()
        .route("/.well-known/webfinger", get(crate::webfinger::handler))
        .route("/.well-known/jwks.json", get(crate::jwt::jwks_handler))
        .route(
            "/.well-known/openid-configuration",
            get(crate::openid_configuration::handler),
        )
        .nest("/auth", auth::router())
        .nest_service("/api", api::service(&state))
        .method_not_allowed_fallback(method_not_allowed_fallback)
        .fallback(get(web_proxy))
        .with_state(state)
}

fn generate_secure_hash(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

async fn create_admin() {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    print!("Username: ");
    stdout().flush().unwrap();
    let mut username = String::new();
    stdin().read_line(&mut username).unwrap();
    let username = username.trim();

    print!("Email: ");
    stdout().flush().unwrap();
    let mut email = String::new();
    stdin().read_line(&mut email).unwrap();
    let email = email.trim();

    let password = rpassword::prompt_password("Password: ").unwrap();
    if password.is_empty() || password.len() < 8 {
        eprintln!("Password is too short.");
        return;
    }

    let password_confirmation = rpassword::prompt_password("Confirm Password: ").unwrap();
    if password != password_confirmation {
        eprintln!("Passwords do not match.");
        return;
    }

    let user_id = sqlx::query!(
        "INSERT INTO users (username, email, is_admin) VALUES ($1, $2, $3) RETURNING id",
        username,
        email,
        true
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .id;

    let password_hash = generate_secure_hash(&password).unwrap();

    sqlx::query!(
        "INSERT INTO auth_local_credentials (user_id, password_hash) VALUES ($1, $2)",
        user_id,
        password_hash
    )
    .execute(&pool)
    .await
    .unwrap();
}

async fn create_oauth2_client() {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    print!("Name: ");
    stdout().flush().unwrap();
    let mut name = String::new();
    stdin().read_line(&mut name).unwrap();
    let name = name.trim();

    print!("Redirect URI: ");
    stdout().flush().unwrap();
    let mut redirect_uri = String::new();
    stdin().read_line(&mut redirect_uri).unwrap();
    let redirect_uri = redirect_uri.trim();

    let client = crate::auth::oauth2::create_client(&pool, &name)
        .await
        .unwrap();

    crate::auth::oauth2::create_client_redirect_uri(&pool, &client.id, redirect_uri)
        .await
        .unwrap();

    println!("Client ID: {}", client.id);
    println!("Client Secret: {}", client.secret);
}

async fn generate_cookie_key() {
    println!("COOKIE_KEY: {}", generate_secure_string!(64))
}

async fn migrate() {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let migrator = sqlx::migrate!();
    migrator.run(&pool).await.unwrap()
}

async fn migrate_undo(target: i64) {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let migrator = sqlx::migrate!();
    migrator.undo(&pool, target).await.unwrap()
}

/*
async fn csp_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if let Some(content_type) = content_type {
        if content_type.starts_with("text/html") {
            headers.insert(
                axum::http::header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
                    .parse()
                    .unwrap(),
            );
        }
    }

    response
}
*/

async fn server() {
    let web_dir = match std::env::var("WEB_DIR") {
        Ok(value) => std::path::PathBuf::from(value),
        Err(_) => std::path::PathBuf::from("apps/web/build"),
    };

    #[cfg(debug_assertions)]
    {
        let _child = std::process::Command::new("npm")
            .arg("run")
            .arg("dev")
            .current_dir(web_dir)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
    }
    #[cfg(not(debug_assertions))]
    {
        let _child = std::process::Command::new("node")
            .arg(web_dir)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    let app = app().await.layer(
        ServiceBuilder::new().layer(TraceLayer::new_for_http()), // .layer(axum::middleware::from_fn(csp_middleware)),
    );
    axum::serve(listener, app).await.unwrap();
}

fn main() {
    let args = Args::parse();
    match args.command {
        Command::CreateAdmin => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(create_admin()),
        Command::CreateOauth2Client => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(create_oauth2_client()),
        Command::GenerateCookieKey => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(generate_cookie_key()),
        Command::Migrate => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(migrate()),
        Command::MigrateUndo { target } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(migrate_undo(target)),
        Command::Server => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(server()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn forgejo_webhook() {
        let app = app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/forgejo/webhook")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("user-agent", "GitHub-Hookshot/0123456")
                    .body(Body::from(
                        serde_json::to_vec(&json!([1, 2, 3, 4])).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            json!({"type": "MissingHeader", "key": "x-forgejo-event"})
        );
    }

    #[tokio::test]
    async fn forgejo_webhook_method_not_allowed() {
        let app = app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/forgejo/webhook")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({"type": "MethodNotAllowed", "method": "GET"}));
    }

    #[tokio::test]
    async fn bad_gateway() {
        let app = app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/bad-gateway")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.is_empty(), true);
    }

    #[tokio::test]
    async fn api_not_found() {
        let app = app().await;
        let response = app
            .oneshot(Request::builder().uri("/api").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({"type": "NotFound", "uri": "/api"}));
    }

    #[tokio::test]
    async fn api_slash_not_found() {
        let app = app().await;
        let response = app
            .oneshot(Request::builder().uri("/api/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({"type": "NotFound", "uri": "/api/"}));
    }
}
