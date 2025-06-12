use crate::api::ApiResult;

use axum::{body::Body, http::StatusCode, response::Response};

pub async fn handler() -> ApiResult<Response> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("not found"))?;

    Ok(response)
}
