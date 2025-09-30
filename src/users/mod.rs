pub mod sql;

use crate::{AppState, api::ApiResult};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use time::{OffsetDateTime, serde::iso8601};

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    #[serde(with = "iso8601")]
    pub created_at: OffsetDateTime,
    #[serde(with = "iso8601")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct PublicUser {
    pub id: i64,
    pub username: String,
    #[serde(with = "iso8601")]
    pub created_at: OffsetDateTime,
}

pub async fn list_users(State(state): State<AppState>, user: Option<User>) -> ApiResult<Response> {
    let Some(user) = user else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let pool = &state.pool;
    if user.is_admin
    {
        let users = sql::users(pool).await?;
        Ok(Json(users).into_response())
    } else {
        let public_users = sql::public_users(pool).await?;
        Ok(Json(public_users).into_response())
    }
}
