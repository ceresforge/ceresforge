use crate::jwt::{Jwk, Jwks};
use sqlx::{Error, Executor, PgPool, Postgres};

pub async fn add_jwk(
    executor: impl Executor<'_, Database = Postgres> + std::marker::Copy,
    jwk: &Jwk,
) -> Result<(), Error> {
    sqlx::query!(
        r#"
        INSERT INTO auth_jwks (kid, n, e)
        SELECT $1, $2, $3
        WHERE NOT EXISTS (
            SELECT 1 FROM auth_jwks WHERE kid = $1
        )
        "#,
        jwk.kid,
        jwk.n,
        jwk.e
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_jwks(executor: impl Executor<'_, Database = Postgres>) -> Result<Jwks, Error> {
    let records = sqlx::query!(
        r#"
        SELECT kid, n, e FROM auth_jwks ORDER BY created_at DESC
        "#,
    )
    .fetch_all(executor)
    .await?;
    let keys = records
        .into_iter()
        .map(|r| Jwk {
            kty: "RSA",
            key_use: "sig",
            alg: "RS256",
            kid: r.kid,
            n: r.n,
            e: r.e,
        })
        .collect();
    Ok(Jwks { keys })
}
