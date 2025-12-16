pub mod error;
mod ws;

pub use crate::api::error::ApiError;
pub type ApiResult<T> = Result<T, ApiError>;

use crate::{
    AppState,
    api::error::{MalformedHeader, MethodNotAllowed, MissingHeader, NotFound},
};
use axum::{
    Json, Router,
    extract::OriginalUri,
    http::{HeaderMap, Method},
    response::{IntoResponse, Response},
    routing::{any, get},
};

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let crate::api::ApiError::InternalServerError(ref err) = self {
            println!("ApiError::InternalServerError {}", err)
        }
        (self.status(), Json(self)).into_response()
    }
}

pub fn header_get_required<'a>(headers: &'a HeaderMap, key: &str) -> ApiResult<&'a str> {
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
    NotFound::new(uri.to_string()).into()
}

pub fn service(state: &AppState) -> Router {
    Router::new()
        .route("/ws", any(ws::handler))
        .route("/users", get(crate::users::list_users))
        .route("/users/self", get(crate::users::get_current_user))
        .nest("/forgejo", crate::forgejo::routes())
        .method_not_allowed_fallback(method_not_allowed_fallback)
        .fallback(fallback)
        .with_state(state.clone())
}
