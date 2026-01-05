pub mod local;
pub mod oauth2;
pub mod saml; // TODO: Change to private
pub mod sql;

use crate::AppState;
use crate::api::ApiResult;
use crate::frontend::FrontendResult;
use crate::users::User;
use axum::extract::State;
use axum::{
    Router,
    extract::Query,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, Key};
use reqwest::StatusCode;
use serde::Deserialize;
use sqlx::PgPool;
use time::Duration;

enum AuthError {
    UsernameNotFound,
    NoPasswordSet,
    InvalidPassword,
}

impl AuthError {
    fn to_user_message(&self) -> &'static str {
        match self {
            AuthError::UsernameNotFound => "Username not found, please sign up.",
            AuthError::NoPasswordSet => "No password set, please try another login method.",
            AuthError::InvalidPassword => "Invalid password, please try again.",
        }
    }
}

fn is_valid_redirect(redirect: &str) -> bool {
    if redirect == "/" {
        return true;
    }
    !redirect.is_empty()
        && redirect.starts_with('/')
        && !redirect.starts_with("//")
        && !redirect.starts_with("/\\")
}

use serde::Deserializer;
fn deserialize_next<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let redirect: Option<String> = Option::deserialize(deserializer)?;
    Ok(redirect.and_then(|s| if is_valid_redirect(&s) { Some(s) } else { None }))
}

#[derive(Deserialize)]
struct Params {
    #[serde(default, deserialize_with = "deserialize_next")]
    next: Option<String>,
}

fn redirect_uri(uri: &str, redirect: Option<&str>) -> String {
    if let Some(s) = redirect {
        let value = urlencoding::encode(s);
        format!("{}?redirect={}", uri, value)
    } else {
        uri.to_string()
    }
}

pub fn login_required_uri(uri: &str, user: &Option<User>) -> String {
    if user.is_none() {
        redirect_uri("/auth/login", Some(uri))
    } else {
        uri.to_string()
    }
}

fn already_logged_in() -> Response {
    StatusCode::NOT_IMPLEMENTED.into_response()
    /*
    let title = "Login";
    let description = "You're already logged in.";
    html! {
        (base(&title, description, html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p .warning {
                    (description)
                }
            }
        }))
    }
    .into_response()
    */
}

fn not_logged_in() -> Response {
    StatusCode::NOT_IMPLEMENTED.into_response()
    /*
    let title = "Logout";
    let description = "You're not logged in.";
    html! {
        (base(&title, description, html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p .warning {
                    (description)
                }
            }
        }))
    }
    .into_response()
    */
}

fn generate_cookie_id() -> String {
    generate_secure_string!(32)
}

async fn create_cookie(pool: &PgPool, key: &Key, user_id: i64) -> ApiResult<(String, String)> {
    let id = generate_cookie_id();
    sqlx::query!(
        "INSERT INTO auth_cookies (id, user_id) VALUES ($1, $2)",
        id,
        user_id
    )
    .execute(pool)
    .await?;

    let mut jar = cookie::CookieJar::new();
    jar.private_mut(key).add(Cookie::new("id", id));
    let plain = jar.get("id").cloned().unwrap();
    let name = plain.name().to_string();
    let value = plain.value().to_string();
    Ok((name, value))
}

/* TODO, delete? */
async fn create_cookie_frontend(
    pool: &PgPool,
    jar: PrivateCookieJar,
    user_id: i64,
    next: Option<&str>,
) -> FrontendResult<Response> {
    let id = generate_cookie_id();
    sqlx::query!(
        "INSERT INTO auth_cookies (id, user_id) VALUES ($1, $2)",
        id,
        user_id
    )
    .execute(pool)
    .await?;
    let cookie = Cookie::build(("id", id))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax);
    let updated_jar = jar.add(cookie);
    Ok((
        updated_jar,
        Redirect::to(next.unwrap_or("/")).into_response(),
    )
        .into_response())
}

async fn login(
    State(state): State<AppState>,
    user: Option<User>,
    Query(params): Query<Params>,
) -> FrontendResult<Response> {
    if user.is_some() {
        return Ok(already_logged_in());
    }
    let next = params.next.as_deref();

    let pool = &state.pool;
    let providers = sqlx::query_as!(
        crate::record::SamlProvider,
        "SELECT * FROM auth_saml_providers"
    )
    .fetch_all(pool)
    .await?;

    Ok(StatusCode::NOT_IMPLEMENTED.into_response())

    /*
    let title = "Login";
    let description = "Please log in using one of the available options.";
    let body = html! {
        div .full-screen {
            h1 {
                (title)
            }
            p {
                (description)
            }
            div .flex-columns {
                a .button .center-fill href=(redirect_uri("/auth/local/login", redirect)) {
                    "Log in"
                }
                @for provider in &providers {
                    a .button .blue-bg .center-fill href=(redirect_uri(&format!("/auth/saml/login/{}", provider.slug), redirect)) {
                        "Log in with " (provider.name)
                    }
                }
            }
        }
    };

    Ok(html! {
        (base(title, description, body))
    }
    .into_response())
    */
}

async fn logout_frontend(
    user: Option<User>,
    jar: PrivateCookieJar,
    State(state): State<AppState>,
) -> FrontendResult<Response> {
    if user.is_none() {
        return Ok(not_logged_in());
    }
    let pool = &state.pool;
    let redirect = Redirect::to("/").into_response();
    match jar.get("id") {
        None => Ok(redirect),
        Some(cookie) => {
            let id = cookie.value_trimmed().to_string();
            sqlx::query!("DELETE FROM auth_cookies WHERE id = $1", &id)
                .execute(pool)
                .await?;

            let cookie = Cookie::build(("id", id))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(axum_extra::extract::cookie::SameSite::Lax)
                .max_age(Duration::ZERO);

            let updated_jar = jar.add(cookie);
            Ok((updated_jar, redirect).into_response())
        }
    }
}

pub async fn logout(
    user: Option<User>,
    jar: PrivateCookieJar,
    State(state): State<AppState>,
) -> ApiResult<Response> {
    if user.is_none() {
        return Ok(not_logged_in());
    }
    let pool = &state.pool;
    match jar.get("id") {
        None => Ok(StatusCode::BAD_REQUEST.into_response()),
        Some(cookie) => {
            let id = cookie.value_trimmed().to_string();
            sqlx::query!("DELETE FROM auth_cookies WHERE id = $1", &id)
                .execute(pool)
                .await?;

            let cookie = Cookie::build(("id", id))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(axum_extra::extract::cookie::SameSite::Lax)
                .max_age(Duration::ZERO);

            let updated_jar = jar.add(cookie);
            Ok((updated_jar, StatusCode::OK.into_response()).into_response())
        }
    }
}

async fn auth(State(state): State<AppState>, user: Option<User>) -> FrontendResult<Response> {
    let pool = &state.pool;
    let providers = sqlx::query_as!(
        crate::record::SamlProvider,
        "SELECT * FROM auth_saml_providers"
    )
    .fetch_all(pool)
    .await?;

    Ok(StatusCode::NOT_IMPLEMENTED.into_response())

    /*
    let title = "Auth";
    let description = "Authenticate to CeresForge.";
    let body = html! {
        div .full-screen {
            h1 {
                (title)
            }
            p {
                (description)
            }
            div .flex-columns {
                @if user.is_none() {
                    a .button .center-fill href="/auth/local/login" {
                        "Log in"
                    }
                    @for provider in &providers {
                        a .button .blue-bg .center-fill href={"/auth/saml/login/" (provider.slug)} {
                            "Log in with " (provider.name)
                        }
                    }
                }
                @else {
                    @for provider in &providers {
                        a .button .blue-bg .center-fill href={"/auth/saml/connect/" (provider.slug)} {
                            "Connect with " (provider.name)
                        }
                    }
                    a .button .red-bg .center-fill href="/auth/logout" {
                        "Log out"
                    }
                }
            }
        }
    };
    Ok(html! {
        (base(title, description, body))
    }
    .into_response())
    */
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(auth))
        .route("/login", get(login))
        .route("/logout", get(logout_frontend))
        // .nest("/local", local::routes())
        .nest("/oauth2", oauth2::routes())
        .nest("/saml", saml::routes())
}
