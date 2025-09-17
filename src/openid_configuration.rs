use crate::api::ApiResult;

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct OpenidConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

pub async fn handler() -> ApiResult<Response> {
    let domain = std::env::var("DOMAIN")?;
    let authorization_endpoint = format!("{}/auth/oauth2/authorize", domain);
    let token_endpoint = format!("{}/auth/oauth2/token", domain);
    let jwks_uri = format!("{}/.well-known/jwks.json", domain);

    let configuration = OpenidConfiguration {
        issuer: domain,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
    };
    Ok(Json(configuration).into_response())
}
