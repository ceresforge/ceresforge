use crate::{
    AppState, auth::login_required_uri, base, frontend::FrontendResult, generate_secure_hash,
    plain_400, record::User,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{Form, OriginalUri, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use maud::html;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use url::Url;

#[derive(Debug)]
pub struct Client {
    pub id: String,
    pub secret: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Payload {
    action: String,
}

#[derive(Debug, Deserialize)]
struct TokenPayload {
    grant_type: String,
    code: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

#[derive(Debug, Serialize)]
struct TokenGrant {
    access_token: String,
    token_type: String,
    refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

fn generate_authorization_code() -> String {
    generate_secure_string!(16)
}

fn generate_client_id() -> String {
    generate_secure_string!(24)
}

fn generate_client_secret() -> String {
    generate_secure_string!(32)
}

fn generate_access_token() -> String {
    generate_secure_string!(32)
}

fn generate_refresh_token() -> String {
    generate_secure_string!(32)
}

pub async fn create_client(pool: &PgPool, name: &str) -> Result<Client, sqlx::Error> {
    let id = generate_client_id();
    let secret = generate_client_secret();
    let secret_hash = generate_secure_hash(&secret).unwrap();
    // TODO: Check rows_affected()
    let _result = sqlx::query!(
        r#"
        INSERT INTO
            auth_oauth2_clients
            (id, secret_hash, name)
        VALUES ($1, $2, $3)
        "#,
        id,
        secret_hash,
        name,
    )
    .execute(pool)
    .await?;
    Ok(Client { id, secret })
}

pub async fn create_client_redirect_uri(
    pool: &PgPool,
    id: &str,
    redirect_uri: &str,
) -> Result<(), sqlx::Error> {
    // TODO: Check rows_affected()
    let _result = sqlx::query!(
        r#"
        INSERT INTO
            auth_oauth2_client_redirect_uris
            (client_id, uri)
        VALUES ($1, $2)
        "#,
        id,
        redirect_uri,
    )
    .execute(pool)
    .await?;
    Ok(())
}

fn authorize_form(path_and_query: &str) -> Response {
    let title = "Authorize";
    let description = "Allow?";
    html! {
        (base(&title, description, html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p {
                    (description)
                }
                form method="POST" action=(path_and_query) {
                    div {
                        button type="submit" name="action" value="allow" { "Allow" }
                        button type="submit" name="action" value="deny" class="red-bg" { "Deny" }
                    }
                }
            }
        }))
    }
    .into_response()
}

async fn authorize_get(user: Option<User>, uri: OriginalUri) -> FrontendResult<Response> {
    let path_and_query = uri.path_and_query().unwrap().as_str();
    if user.is_none() {
        return Ok(Redirect::temporary(&login_required_uri(path_and_query, &user)).into_response());
    }
    Ok(authorize_form(path_and_query))
}

async fn authorize_post(
    State(state): State<AppState>,
    user: Option<User>,
    uri: OriginalUri,
    Query(params): Query<AuthorizeParams>,
    Form(payload): Form<Payload>,
) -> FrontendResult<Response> {
    let path_and_query = uri.path_and_query().unwrap().as_str();
    let user = match user {
        Some(user) => user,
        None => {
            return Ok(
                Redirect::temporary(&login_required_uri(path_and_query, &user)).into_response(),
            );
        }
    };
    if payload.action != "allow" {
        return Ok("Denied".into_response());
    }
    if params.response_type != "code" {
        return Ok(plain_400());
    }
    let scopes = match params.scope {
        None => "".to_string(),
        Some(s) => {
            if s == "openid" {
                s
            }
            else {
                return Ok(plain_400());
            }
        },
    };

    let client_id = params.client_id.as_str();

    let pool = &state.pool;
    let records = sqlx::query!(
        r#"
        SELECT uri FROM auth_oauth2_client_redirect_uris WHERE client_id = $1
        "#,
        client_id
    )
    .fetch_all(pool)
    .await?;

    if records.len() == 0 {
        return Ok(plain_400());
    }
    let redirect_uri = match params.redirect_uri {
        None => {
            if records.len() != 1 {
                return Ok(plain_400());
            }
            &records[0].uri
        }
        Some(s) => match records.iter().find(|record| record.uri == *s) {
            Some(record) => &record.uri,
            None => return Ok(plain_400()),
        },
    };

    let code = generate_authorization_code();

    // TODO: Check rows_affected()
    let _result = sqlx::query!(
        r#"
        INSERT INTO
            auth_oauth2_client_authorization_codes
            (code, client_id, user_id, redirect_uri, scopes)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        code,
        client_id,
        user.id,
        redirect_uri,
        scopes
    )
    .execute(pool)
    .await?;

    let mut callback_uri = Url::parse(&redirect_uri).unwrap();
    callback_uri.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = params.state {
        callback_uri.query_pairs_mut().append_pair("state", &state);
    }
    Ok(Redirect::to(callback_uri.as_str()).into_response())
}

// TODO: no-cache and no-store headers
async fn token(
    State(state): State<AppState>,
    Form(payload): Form<TokenPayload>,
) -> FrontendResult<Response> {
    if payload.grant_type != "authorization_code" {
        return Ok(plain_400());
    }
    let client_id = payload.client_id;

    let pool = &state.pool;
    let record = sqlx::query!(
        r#"
        SELECT
            c.secret_hash,
            ac.user_id,
            ac.scopes
        FROM
            auth_oauth2_client_authorization_codes AS ac
        INNER JOIN
            auth_oauth2_clients AS c ON ac.client_id = c.id
        WHERE
            ac.code = $1
            AND ac.client_id = $2
            AND ac.redirect_uri = $3
            AND ac.expires_at > now()
            AND ac.completed_at IS NULL
        "#,
        &payload.code,
        &client_id,
        &payload.redirect_uri,
    )
    .fetch_optional(pool)
    .await?;
    let record = match record {
        None => return Ok(plain_400()),
        Some(record) => record,
    };
    
    let user_id = record.user_id;

    let parsed_hash = PasswordHash::new(&record.secret_hash)?;
    let verified =
        Argon2::default().verify_password(payload.client_secret.as_bytes(), &parsed_hash);
    if verified.is_err() {
        return Ok(plain_400());
    }

    let result = sqlx::query!(
        r#"
        UPDATE
            auth_oauth2_client_authorization_codes
        SET
            completed_at = now()
        WHERE
            code = $1
            AND client_id = $2
            AND redirect_uri = $3
            AND expires_at > now()
            AND completed_at IS NULL
        "#,
        &payload.code,
        &client_id,
        &payload.redirect_uri,
    )
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(plain_400());
    }

    let access_token = generate_access_token();
    // TODO: Check rows_affected
    let _result = sqlx::query!(
        r#"
        INSERT INTO
            auth_oauth2_client_access_tokens
            (id, client_id, user_id, scopes)
        VALUES
            ($1, $2, $3, $4)
        "#,
        &access_token,
        &client_id,
        user_id,
        record.scopes,
    )
    .execute(pool)
    .await?;

    let refresh_token = generate_refresh_token();
    // TODO: Check rows_affected
    let _result = sqlx::query!(
        r#"
        INSERT INTO
            auth_oauth2_client_refresh_tokens
            (id, client_id, user_id, scopes)
        VALUES
            ($1, $2, $3, $4)
        "#,
        &access_token,
        &client_id,
        user_id,
        record.scopes,
    )
    .execute(pool)
    .await?;

    let id_token: Option<String> = match record.scopes.as_str() {
        "" => None,
        "openid" => Some(crate::jwt::generate_id_token(&state.jwt_rsa_key, user_id, &client_id)),
        _ => None,
    };
    let grant = TokenGrant {
        access_token,
        token_type: "Bearer".to_string(),
        refresh_token,
        id_token,
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());

    Ok((StatusCode::OK, headers, Json(grant).into_response()).into_response())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/token", post(token))
}
