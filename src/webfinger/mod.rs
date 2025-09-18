use crate::api::ApiResult;

use axum::{
    Json,
    extract::Query,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Deserialize)]
pub struct WebFingerPayload {
    rel: String,
    resource: String,
}

#[derive(Debug, Serialize)]
struct JrdLink {
    rel: String,
    #[serde(rename = "type")]
    type_field: String,
    href: String,
}

#[derive(Debug, Serialize)]
struct Jrd {
    subject: String,
    links: Vec<JrdLink>,
}

pub async fn handler(Query(payload): Query<WebFingerPayload>) -> ApiResult<Response> {
    dbg!(&payload);
    if payload.rel != "http://openid.net/specs/connect/1.0/issuer" {
        return Ok((StatusCode::NOT_FOUND).into_response());
    }
    let acct = if let Some(s) = payload.resource.strip_prefix("acct:") {
        s
    } else {
        return Ok((StatusCode::BAD_REQUEST, "Resource must start with acct:").into_response());
    };
    // TODO: Check user
    let Some((_user, domain)) = acct.split_once('@') else {
        return Ok((StatusCode::BAD_REQUEST, "Invalid resource format").into_response());
    };

    let base_url = std::env::var("BASE_URL")?;
    let url = Url::parse(&base_url).unwrap();
    if url.host_str().unwrap() != domain {
        return Ok((StatusCode::BAD_REQUEST, "No match").into_response());
    }
    let oidc_discovery_url = format!("{}/.well-known/openid-configuration", &base_url);

    let jrd = Jrd {
        subject: payload.resource,
        links: vec![JrdLink {
            rel: "http://openid.net/specs/connect/1.0/issuer".to_string(),
            type_field: "application/json".to_string(),
            href: oidc_discovery_url,
        }],
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/jrd+json".parse().unwrap(),
    );
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());

    Ok((StatusCode::OK, headers, Json(jrd)).into_response())
}
