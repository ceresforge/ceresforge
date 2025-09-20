use sqlx::{Error, PgPool};

pub async fn is_admin(pool: &PgPool, username: &str) -> Result<bool, Error> {
    let result = sqlx::query!(
        r#"
        SELECT is_admin FROM users WHERE username = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await?;
    Ok(result.map_or(false, |record| record.is_admin))
}
