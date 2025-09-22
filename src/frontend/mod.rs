pub mod error;

use crate::plain_500;
use axum::response::{IntoResponse, Response};
use error::FrontendError;

pub type FrontendResult<T> = Result<T, FrontendError>;

impl IntoResponse for FrontendError {
    fn into_response(self) -> Response {
        println!("{}", self);
        plain_500()
    }
}
