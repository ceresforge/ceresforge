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

use crate::auth::saml;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use axum::{
    Router,
    body::Body,
    extract::{FromRef, OriginalUri, State, WebSocketUpgrade},
    http::{HeaderMap, Request, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::cookie::Key;
use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::io::{Write, stdin, stdout};
use std::time::Duration;
use tokio::{io::AsyncBufReadExt, signal};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth::sql::add_jwk;

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
    MigrateUndo { target: i64 },
    Server,
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    key: Key,
    jwt_rsa_key: RsaPrivateKey,
    client: Client<HttpConnector, Body>,
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
*/

async fn method_not_allowed_fallback() -> impl IntoResponse {
    StatusCode::METHOD_NOT_ALLOWED
}

async fn proxy(
    State(state): State<AppState>,
    mut req: Request<Body>,
) -> Result<Response, StatusCode> {
    let is_websocket = req
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase() == "websocket")
        .unwrap_or(false);
    if is_websocket {
        return Err(StatusCode::NOT_IMPLEMENTED);
    }

    let sveltekit_port = if cfg!(debug_assertions) { 5173 } else { 3000 };
    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);
    let uri = format!("http://127.0.0.1:{sveltekit_port}{path_query}");
    *req.uri_mut() = Uri::try_from(uri).unwrap();
    req.headers_mut().remove(header::HOST);

    Ok(state
        .client
        .request(req)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .into_response())
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

    let jwk = crate::jwt::get_jwk(&jwt_rsa_key);
    match add_jwk(&pool, &jwk).await {
        Ok(_) => (),
        Err(_) => () // TODO
    }

    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    let state = AppState {
        pool,
        key,
        jwt_rsa_key,
        client,
    };

    Router::new()
        .route("/.well-known/webfinger", get(crate::webfinger::handler))
        .route("/.well-known/jwks.json", get(crate::jwt::jwks_handler))
        .route("/metadata/{provider}", get(saml::metadata))
        .route(
            "/.well-known/openid-configuration",
            get(crate::openid_configuration::handler),
        )
        // .nest("/auth", auth::router())
        .nest_service("/api", api::service(&state))
        .method_not_allowed_fallback(method_not_allowed_fallback)
        .fallback(proxy)
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

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { },
        _ = terminate => { },
    }
}

async fn server() {
    let web_dir = match std::env::var("WEB_DIR") {
        Ok(value) => std::path::PathBuf::from(value),
        Err(_) => std::path::PathBuf::from("apps/web/build"),
    };

    let mut child = if cfg!(debug_assertions) {
        tokio::process::Command::new("npm")
            .args(["run", "dev"])
            .current_dir(web_dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    } else {
        tokio::process::Command::new("node")
            .arg(web_dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };

    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=debug,sveltekit=debug,tower_http=debug",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let line = line.trim();
            if !line.is_empty() {
                tracing::debug!(target: "sveltekit", "{}", line);
            }
        }
    });

    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let line = line.trim();
            if !line.is_empty() {
                tracing::error!(target: "sveltekit", "{}", line);
            }
        }
    });

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("Listening on http://{}", listener.local_addr().unwrap());

    let app = app().await.layer(
        ServiceBuilder::new().layer(TraceLayer::new_for_http().on_request(())), // .layer(axum::middleware::from_fn(csp_middleware)),
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    drop(stdin);
    match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(Ok(status)) => {
            tracing::debug!(target: "sveltekit", "exited with {status}");
        }
        Ok(Err(err)) => {
            tracing::error!(target: "sveltekit", "{err}");
            let _ = child.kill().await;
        }
        Err(_) => {
            tracing::warn!(target: "sveltekit", "timeout");
            let _ = child.kill().await;
        }
    }
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
