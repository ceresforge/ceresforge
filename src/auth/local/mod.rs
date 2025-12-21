use super::{Params, already_logged_in, create_cookie, redirect_uri};
use crate::{AppState, frontend::FrontendResult};
use crate::{auth::AuthError, users::User};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use axum::{
    Router,
    extract::{Form, Query, State},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::cookie::PrivateCookieJar;
use reqwest::StatusCode;
use serde::Deserialize;

#[derive(Deserialize)]
struct Payload {
    username: String,
    password: String,
}

fn login_form(err: Option<AuthError>, username: Option<&str>, redirect: Option<&str>) -> Response {
    StatusCode::NOT_IMPLEMENTED.into_response()
    /*
    let title = "Login";
    let description = "Please enter your username and password.";
    let action = redirect_uri("/auth/local/login", redirect.as_deref());
    let body = html! {
        div .full-screen {
            h1 {
                (title)
            }
            p {
                (description)
            }
            @if let Some(err) = err {
                p .error { (err.to_user_message()) }
            }
            form action=(action) method="POST" {
                input
                    type="text"
                    id="username"
                    name="username"
                    autocomplete="username"
                    placeholder="Username"
                    autofocus[username.is_none()]
                    value=[username]
                    required;
                input
                    type="password"
                    id="password"
                    name="password"
                    autocomplete="current-password"
                    placeholder="Password"
                    autofocus[username.is_some()]
                    required;
                button type="submit" {
                    "Log in"
                }
            }
        }
    };
    html! {
        (base(title, description, body))
    }
    .into_response()
    */
}

async fn verify(
    pool: &sqlx::PgPool,
    username: &str,
    password: &str,
) -> FrontendResult<Result<i64, AuthError>> {
    let optional = sqlx::query!(
        r#"
        SELECT
            users.id,
            auth_local_credentials.password_hash AS "password_hash?"
        FROM users
        LEFT JOIN auth_local_credentials
        ON users.id = auth_local_credentials.user_id
        WHERE users.username = $1
        "#,
        username
    )
    .fetch_optional(pool)
    .await?;

    match optional {
        None => Ok(Err(AuthError::UsernameNotFound)),
        Some(record) => {
            let user_id = record.id;
            match record.password_hash {
                None => Ok(Err(AuthError::NoPasswordSet)),
                Some(password_hash) => {
                    let parsed_hash = PasswordHash::new(&password_hash)?;
                    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
                        Ok(_) => Ok(Ok(user_id)),
                        Err(_) => Ok(Err(AuthError::InvalidPassword)),
                    }
                }
            }
        }
    }
}

async fn login_get(user: Option<User>, Query(params): Query<Params>) -> FrontendResult<Response> {
    if user.is_some() {
        return Ok(already_logged_in());
    }
    let redirect = params.redirect.as_deref();
    Ok(login_form(None, None, redirect))
}

async fn login_post(
    user: Option<User>,
    jar: PrivateCookieJar,
    State(state): State<AppState>,
    Query(params): Query<Params>,
    Form(payload): Form<Payload>,
) -> FrontendResult<Response> {
    if user.is_some() {
        return Ok(already_logged_in());
    }
    let pool = &state.pool;
    let redirect = params.redirect.as_deref();
    let username = &payload.username;
    let result = verify(pool, username, &payload.password).await?;
    match result {
        Ok(user_id) => create_cookie(pool, jar, user_id, redirect).await,
        Err(err) => match err {
            AuthError::InvalidPassword => Ok(login_form(Some(err), Some(username), redirect)),
            _ => Ok(login_form(Some(err), None, redirect)),
        },
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/login", get(login_get).post(login_post))
}
