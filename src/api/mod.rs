pub mod error;

pub use crate::api::error::ApiError;
pub type Result<T> = std::result::Result<T, ApiError>;

use crate::api::error::{MalformedHeader, MethodNotAllowed, MissingHeader, ResourceNotFound};
use axum::{
    Json, Router,
    extract::OriginalUri,
    http::{HeaderMap, Method},
    response::{IntoResponse, Response},
};

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status(), Json(self)).into_response()
    }
}

pub fn header_get_required<'a>(headers: &'a HeaderMap, key: &str) -> Result<&'a str> {
    match headers.get(key) {
        Some(val) => match val.to_str() {
            Ok(s) => Ok(s),
            Err(source) => Err(MalformedHeader::new(key.to_string(), source).into()),
        },
        None => Err(MissingHeader::new(key.to_string()).into()),
    }
}

async fn method_not_allowed_fallback(method: Method) -> ApiError {
    MethodNotAllowed::new(method.to_string()).into()
}

async fn fallback(uri: OriginalUri) -> ApiError {
    ResourceNotFound::new(uri.to_string()).into()
}

pub fn routes() -> Router {
    Router::new()
        .nest("/forgejo", crate::forgejo::routes())
        .method_not_allowed_fallback(method_not_allowed_fallback)
        .fallback(fallback)
}
