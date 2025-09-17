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
mod openid_configuration;
mod record;
mod webfinger;

use crate::{frontend::FrontendResult, record::User};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use auth::login_required_uri;
use axum::{
    Router,
    extract::{FromRef, OriginalUri},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::cookie::Key;
use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use maud::{DOCTYPE, Markup, html};
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
    Server,
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    key: Key,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

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

async fn fallback() -> impl IntoResponse {
    plain_404()
}

async fn home(user: Option<User>) -> FrontendResult<Response> {
    let title = "CeresForge";
    let description = "A web platform for learning, creating, and testing software.";
    let body = html! {
        div .full-screen {
            h1 {
                (title)
            }
            p {
                (description)
            }
            div .flex-columns {
                a .button .red-bg .center-fill href=(login_required_uri("/admin", &user)) {
                    "Admin"
                }
            }
        }
    };
    Ok(html! {
        (base(title, description, body))
    }
    .into_response())
}

async fn admin(
    user: Option<User>,
    OriginalUri(uri): OriginalUri,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> FrontendResult<axum::response::Response> {
    if user.is_none() {
        let uri = uri.to_string();
        let uri = urlencoding::encode(&uri);
        let uri = format!("/auth/local/login?redirect={}", uri);
        return Ok(axum::response::Redirect::to(&uri).into_response());
    }
    let user = user.unwrap();
    if !user.is_admin {
        return Ok(plain_403());
    }
    let pool = &state.pool;
    let users = sqlx::query_as!(User, "SELECT * FROM users")
        .fetch_all(pool)
        .await?;
    let title = "Admin";
    let description = "Displays administrator information.";
    let body = html! {
        header {
            nav {
                a href="/" {
                   img src=(SVG_PATH) alt="CeresForge";
                }
                a href="/admin" {
                    "Admin"
                }
                a href="/auth" .button {
                    "Log in"
                }
            }
        }
        main {
            article {
                h1 {
                    (title)
                }
                p {
                    (description)
                }
                table {
                    thead {
                        tr {
                            th { "ID" }
                            th { "Username" }
                            th { "Admin" }
                            th { "Email" }
                            th { "First Name" }
                            th { "Last Name" }
                        }
                    }
                    tbody {
                        @for user in &users {
                        tr {
                            td { (user.id) }
                            td { (user.username) }
                            td {
                                @if user.is_admin {
                                    "✅"
                                }
                                @else {
                                    "❌"
                                }
                            }
                            td {
                                @if let Some(email) = &user.email {
                                    (email)
                                }
                            }
                            td {
                                @if let Some(first_name) = &user.first_name {
                                    (first_name)
                                }
                            }
                            td {
                                @if let Some(last_name) = &user.last_name {
                                    (last_name)
                                }
                            }
                        }
                        }
                    }
                }
            }
        }
    };
    Ok(html! {
        (base(title, description, body))
    }
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

    let state = AppState { pool, key };

    Router::new()
        .route("/", get(home))
        .route("/admin", get(admin))
        .route("/ws-demo", get(ws_demo))
        .route("/ws-demo.css", get(ws_demo_css))
        .route("/ws-demo.js", get(ws_demo_js))
        .route(CSS_PATH, get(css))
        .route("/inter-normal-4.1.woff2", get(inter_normal))
        .route("/inter-italic-4.1.woff2", get(inter_italic))
        .route(SVG_PATH, get(svg))
        .route("/.well-known/webfinger", get(crate::webfinger::handler))
        .route(
            "/.well-known/openid-configuration",
            get(crate::openid_configuration::handler),
        )
        .nest("/auth", auth::routes())
        .nest_service("/api", api::routes())
        .method_not_allowed_fallback(method_not_allowed_fallback)
        .fallback(fallback)
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

    sqlx::migrate!().run(&pool).await.unwrap()
}

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

async fn server() {
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
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(axum::middleware::from_fn(csp_middleware)),
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
    async fn not_found() {
        let app = app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/not-found")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
