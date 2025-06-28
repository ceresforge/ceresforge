use std::error::Error;

#[derive(Debug)]
#[non_exhaustive]
pub enum FrontendError {
    InternalError(InternalError),
}

impl std::fmt::Display for FrontendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            FrontendError::InternalError(err) => write!(f, "{err}"),
        }
    }
}

#[derive(Debug)]
pub struct InternalError {
    source: Option<Box<dyn Error>>,
}

impl InternalError {
    pub fn new(source: Box<dyn Error>) -> Self {
        InternalError {
            source: Some(source),
        }
    }
    pub fn new_unknown() -> Self {
        InternalError { source: None }
    }
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.source {
            Some(err) => write!(f, "{}", err),
            None => write!(f, "InternalError"),
        }
    }
}

impl From<std::io::Error> for FrontendError {
    fn from(err: std::io::Error) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<std::env::VarError> for FrontendError {
    fn from(err: std::env::VarError) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<std::string::FromUtf8Error> for FrontendError {
    fn from(err: std::string::FromUtf8Error) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<argon2::password_hash::Error> for FrontendError {
    fn from(_err: argon2::password_hash::Error) -> FrontendError {
        FrontendError::InternalError(InternalError::new_unknown())
    }
}

impl From<axum::http::header::InvalidHeaderValue> for FrontendError {
    fn from(err: axum::http::header::InvalidHeaderValue) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<base64::DecodeError> for FrontendError {
    fn from(err: base64::DecodeError) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<quick_xml::errors::serialize::DeError> for FrontendError {
    fn from(err: quick_xml::errors::serialize::DeError) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<quick_xml::errors::serialize::SeError> for FrontendError {
    fn from(err: quick_xml::errors::serialize::SeError) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<serde_json::Error> for FrontendError {
    fn from(err: serde_json::Error) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<sqlx::Error> for FrontendError {
    fn from(err: sqlx::Error) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<time::error::ComponentRange> for FrontendError {
    fn from(err: time::error::ComponentRange) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<time::error::Format> for FrontendError {
    fn from(err: time::error::Format) -> FrontendError {
        FrontendError::InternalError(InternalError::new(Box::new(err)))
    }
}
