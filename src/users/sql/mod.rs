use super::{PublicUser, User};
use sqlx::{Error, Executor, PgPool, Postgres};

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

pub async fn user_by_user_id(
    executor: impl Executor<'_, Database = Postgres>,
    user_id: i64,
) -> Result<User, Error> {
    let result = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE id = $1
        "#,
        user_id,
    )
    .fetch_one(executor)
    .await?;
    Ok(result)
}

pub async fn public_users(
    executor: impl Executor<'_, Database = Postgres>,
) -> Result<Vec<PublicUser>, Error> {
    let result = sqlx::query_as!(
        PublicUser,
        r#"
        SELECT id, username, created_at FROM users LIMIT 100
        "#,
    )
    .fetch_all(executor)
    .await?;
    Ok(result)
}

pub async fn users(executor: impl Executor<'_, Database = Postgres>) -> Result<Vec<User>, Error> {
    let result = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users ORDER BY created_at LIMIT 1000
        "#,
    )
    .fetch_all(executor)
    .await?;
    Ok(result)
}
