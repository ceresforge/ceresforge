pub mod error;

use axum::response::{IntoResponse, Response};
use error::FrontendError;
use reqwest::StatusCode;

pub type FrontendResult<T> = Result<T, FrontendError>;

impl IntoResponse for FrontendError {
    fn into_response(self) -> Response {
        println!("{}", self);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}
