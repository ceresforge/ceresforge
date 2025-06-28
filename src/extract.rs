use crate::{AppState, record::User};
use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use std::convert::Infallible;

impl OptionalFromRequestParts<AppState> for User {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(async {
            let pool = &state.pool;
            let jar = PrivateCookieJar::<Key>::from_request_parts(parts, state)
                .await
                .ok()?;
            let cookie = jar.get("session_id")?;
            let session_id = cookie.value_trimmed();
            sqlx::query_as!(
                User,
                r#"
                SELECT users.*
                FROM sessions
                INNER JOIN users
                ON sessions.user_id = users.id
                WHERE sessions.id = $1
                AND sessions.expires_at > now()
                "#,
                session_id
            )
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
        }
        .await)
    }
}
