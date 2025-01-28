pub mod error;

pub use crate::api::error::Error;
pub type Result<T> = std::result::Result<T, Error>;

use crate::api::error::{MalformedHeader, MethodNotAllowed, MissingHeader, ResourceNotFound};
use axum::{
    Router,
    extract::OriginalUri,
    http::{HeaderMap, Method},
};

pub fn header_get_required<'a>(headers: &'a HeaderMap, key: &'a str) -> Result<&'a str> {
    match headers.get(key) {
        Some(val) => match val.to_str() {
            Ok(s) => Ok(s),
            Err(source) => Err(MalformedHeader::new(key.to_string(), source).into()),
        },
        None => Err(MissingHeader::new(key.to_string()).into()),
    }
}

async fn method_not_allowed_fallback(method: Method) -> Error {
    MethodNotAllowed::new(method.to_string()).into()
}

async fn fallback(uri: OriginalUri) -> Error {
    ResourceNotFound::new(uri.to_string()).into()
}

pub fn routes() -> Router {
    Router::new()
        .nest("/github", crate::github::routes())
        .method_not_allowed_fallback(method_not_allowed_fallback)
        .fallback(fallback)
}
