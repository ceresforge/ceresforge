mod local;
mod saml;

use crate::frontend::FrontendResult;
use crate::record::User;
use crate::{AppState, base};
use axum::extract::State;
use axum::{
    Router,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::Cookie;
use maud::html;
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
fn deserialize_redirect<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let redirect: Option<String> = Option::deserialize(deserializer)?;
    Ok(redirect.and_then(|s| if is_valid_redirect(&s) { Some(s) } else { None }))
}

#[derive(Deserialize)]
struct Params {
    #[serde(default, deserialize_with = "deserialize_redirect")]
    redirect: Option<String>,
}

fn already_logged_in() -> Response {
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
}

fn not_logged_in() -> Response {
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
}

fn generate_session_id() -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn create_session(
    pool: &PgPool,
    jar: PrivateCookieJar,
    user_id: i64,
    redirect: Option<&str>,
) -> FrontendResult<Response> {
    let session_id = generate_session_id();
    sqlx::query!(
        "INSERT INTO sessions (id, user_id) VALUES ($1, $2)",
        session_id,
        user_id
    )
    .execute(pool)
    .await?;
    let cookie = Cookie::build(("session_id", session_id))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax);
    let updated_jar = jar.add(cookie);
    Ok((
        updated_jar,
        Redirect::to(redirect.unwrap_or("/")).into_response(),
    )
        .into_response())
}

async fn logout(
    user: Option<User>,
    jar: PrivateCookieJar,
    State(state): State<AppState>,
) -> FrontendResult<Response> {
    if user.is_none() {
        return Ok(not_logged_in());
    }
    let pool = &state.pool;
    let redirect = Redirect::to("/").into_response();
    match jar.get("session_id") {
        None => Ok(redirect),
        Some(cookie) => {
            let session_id = cookie.value_trimmed().to_string();
            sqlx::query!("DELETE FROM sessions WHERE id = $1", &session_id)
                .execute(pool)
                .await?;

            let cookie = Cookie::build(("session_id", session_id))
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

pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/local", local::routes())
        .nest("/saml", saml::routes())
        .route("/logout", get(logout))
}
