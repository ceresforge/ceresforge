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
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
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
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string()],
        scopes_supported: vec!["openid".to_string()],
    };
    Ok(Json(configuration).into_response())
}
