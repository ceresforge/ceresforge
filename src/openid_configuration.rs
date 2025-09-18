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
    let base_url = std::env::var("BASE_URL")?;
    let authorization_endpoint = format!("{}/auth/oauth2/authorize", &base_url);
    let token_endpoint = format!("{}/auth/oauth2/token", &base_url);
    let jwks_uri = format!("{}/.well-known/jwks.json", &base_url);

    let configuration = OpenidConfiguration {
        issuer: base_url,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
    };
    Ok(Json(configuration).into_response())
}
