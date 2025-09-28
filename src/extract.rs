use crate::{AppState, users::User};
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
            let cookie = jar.get("id")?;
            let id = cookie.value_trimmed();
            sqlx::query_as!(
                User,
                r#"
                SELECT users.*
                FROM auth_cookies
                INNER JOIN users
                ON auth_cookies.user_id = users.id
                WHERE auth_cookies.id = $1
                AND auth_cookies.expires_at > now()
                "#,
                id
            )
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
        }
        .await)
    }
}
