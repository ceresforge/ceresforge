use crate::AppState;
use crate::api::ApiResult;
use crate::auth::create_cookie;
use crate::{auth::AuthError, users::User};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use reqwest::StatusCode;
use serde::Deserialize;

#[derive(Deserialize)]
struct Payload {
    username: String,
    password: String,
}

async fn verify(
    pool: &sqlx::PgPool,
    username: &str,
    password: &str,
) -> ApiResult<Result<i64, AuthError>> {
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
                    // TODO: Fix unwrap
                    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
                    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
                        Ok(_) => Ok(Ok(user_id)),
                        Err(_) => Ok(Err(AuthError::InvalidPassword)),
                    }
                }
            }
        }
    }
}

async fn login(
    State(state): State<AppState>,
    user: Option<User>,
    axum::extract::Json(payload): axum::extract::Json<Payload>,
) -> ApiResult<Response> {
    if user.is_some() {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    }
    let pool = &state.pool;
    let key = &state.key;
    let result = verify(pool, &payload.username, &payload.password).await?;
    match result {
        Ok(user_id) => {
            let (name, value) = create_cookie(pool, key, user_id).await?;
            Ok(axum::Json(serde_json::json!({
                "cookies": [
                    {
                        "name": name,
                        "value": value
                    }
                ],
            }))
            .into_response())
        }
        Err(_err) => Ok(StatusCode::UNAUTHORIZED.into_response()),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/login", post(login))
}
