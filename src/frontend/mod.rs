pub mod error;

use crate::base;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use error::FrontendError;
use maud::html;

pub type FrontendResult<T> = Result<T, FrontendError>;

impl IntoResponse for FrontendError {
    fn into_response(self) -> Response {
        let title = "500";
        let description = "Internal Server Error.";
        let body = html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p {
                    (description)
                }
            }
        };
        let markup = html! {
            (base(title, description, body))
        };
        tracing::error!("{:?}", self);
        (StatusCode::INTERNAL_SERVER_ERROR, markup.into_response()).into_response()
    }
}
