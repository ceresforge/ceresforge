use crate::{AppState, api::ApiResult};

use crate::users::sql::is_admin;
use axum::{
    Json,
    extract::{Query, State},
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

pub async fn handler(
    State(state): State<AppState>,
    Query(payload): Query<WebFingerPayload>,
) -> ApiResult<Response> {
    if payload.rel != "http://openid.net/specs/connect/1.0/issuer" {
        return Ok((StatusCode::NOT_FOUND).into_response());
    }
    let acct = if let Some(s) = payload.resource.strip_prefix("acct:") {
        s
    } else {
        return Ok((StatusCode::BAD_REQUEST, "Resource must start with acct:").into_response());
    };
    let Some((username, domain)) = acct.split_once('@') else {
        return Ok((StatusCode::BAD_REQUEST, "Invalid resource format").into_response());
    };
    let pool = &state.pool;
    if !is_admin(pool, username).await? {
        return Ok((StatusCode::BAD_REQUEST, "Invalid username").into_response());
    }

    let base_url = std::env::var("BASE_URL")?;
    let url = Url::parse(&base_url).unwrap();
    if url.host_str().unwrap() != domain {
        return Ok((StatusCode::BAD_REQUEST, "No match").into_response());
    }

    let jrd = Jrd {
        subject: payload.resource,
        links: vec![JrdLink {
            rel: "http://openid.net/specs/connect/1.0/issuer".to_string(),
            type_field: "application/json".to_string(),
            href: base_url,
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
