use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::{StatusCode, header::ToStrError},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[non_exhaustive]
#[serde(tag = "type")]
pub enum Error {
    InternalServerError(InternalServerError),
    ResourceNotFound(ResourceNotFound),
    MethodNotAllowed(MethodNotAllowed),
    MissingHeader(MissingHeader),
    MalformedHeader(MalformedHeader),
    UnsupportedContentType(UnsupportedContentType),
    InvalidUserAgent(InvalidUserAgent),
    SignatureMismatch(SignatureMismatch),
    JsonError(JsonError),
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Error::InternalServerError(err) => err.status(),
            Error::ResourceNotFound(err) => err.status(),
            Error::MethodNotAllowed(err) => err.status(),
            Error::MissingHeader(err) => err.status(),
            Error::MalformedHeader(err) => err.status(),
            Error::UnsupportedContentType(err) => err.status(),
            Error::InvalidUserAgent(err) => err.status(),
            Error::SignatureMismatch(err) => err.status(),
            Error::JsonError(err) => err.status(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Error::InternalServerError(err) => write!(f, "{err}"),
            Error::ResourceNotFound(err) => write!(f, "{err}"),
            Error::MethodNotAllowed(err) => write!(f, "{err}"),
            Error::MissingHeader(err) => write!(f, "{err}"),
            Error::MalformedHeader(err) => write!(f, "{err}"),
            Error::UnsupportedContentType(err) => write!(f, "{err}"),
            Error::InvalidUserAgent(err) => write!(f, "{err}"),
            Error::SignatureMismatch(err) => write!(f, "{err}"),
            Error::JsonError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::InternalServerError(err) => err.source(),
            Error::ResourceNotFound(err) => err.source(),
            Error::MethodNotAllowed(err) => err.source(),
            Error::MissingHeader(err) => err.source(),
            Error::MalformedHeader(err) => err.source(),
            Error::UnsupportedContentType(err) => err.source(),
            Error::InvalidUserAgent(err) => err.source(),
            Error::SignatureMismatch(err) => err.source(),
            Error::JsonError(err) => err.source(),
        }
    }
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(err: hmac::digest::InvalidLength) -> Error {
        Error::InternalServerError(InternalServerError::new(Box::new(err)))
    }
}

impl From<std::env::VarError> for Error {
    fn from(err: std::env::VarError) -> Error {
        Error::InternalServerError(InternalServerError::new(Box::new(err)))
    }
}

impl From<ResourceNotFound> for Error {
    fn from(err: ResourceNotFound) -> Error {
        Error::ResourceNotFound(err)
    }
}

impl From<MethodNotAllowed> for Error {
    fn from(err: MethodNotAllowed) -> Error {
        Error::MethodNotAllowed(err)
    }
}

impl From<MissingHeader> for Error {
    fn from(err: MissingHeader) -> Error {
        Error::MissingHeader(err)
    }
}

impl From<MalformedHeader> for Error {
    fn from(err: MalformedHeader) -> Error {
        Error::MalformedHeader(err)
    }
}

impl From<UnsupportedContentType> for Error {
    fn from(err: UnsupportedContentType) -> Error {
        Error::UnsupportedContentType(err)
    }
}

impl From<InvalidUserAgent> for Error {
    fn from(err: InvalidUserAgent) -> Error {
        Error::InvalidUserAgent(err)
    }
}

impl From<SignatureMismatch> for Error {
    fn from(err: SignatureMismatch) -> Error {
        Error::SignatureMismatch(err)
    }
}

impl From<JsonRejection> for Error {
    fn from(source: JsonRejection) -> Error {
        Error::JsonError(JsonError::new(source))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status(), Json(self)).into_response()
    }
}

#[derive(Debug, Serialize)]
pub struct InternalServerError {
    #[serde(skip_serializing)]
    source: Box<dyn std::error::Error>,
}

impl InternalServerError {
    pub fn new(source: Box<dyn std::error::Error>) -> Self {
        InternalServerError { source }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl std::fmt::Display for InternalServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for InternalServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug, Serialize)]
pub struct ResourceNotFound {
    uri: String,
}

impl ResourceNotFound {
    pub fn new(uri: String) -> Self {
        ResourceNotFound { uri }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::NOT_FOUND
    }
}

impl std::fmt::Display for ResourceNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.uri)
    }
}

impl std::error::Error for ResourceNotFound {}

#[derive(Debug, Serialize)]
pub struct MethodNotAllowed {
    method: String,
}

impl MethodNotAllowed {
    pub fn new(method: String) -> Self {
        MethodNotAllowed { method }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::METHOD_NOT_ALLOWED
    }
}

impl std::fmt::Display for MethodNotAllowed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.method)
    }
}

impl std::error::Error for MethodNotAllowed {}

#[derive(Debug, Serialize)]
pub struct MissingHeader {
    key: String,
}

impl MissingHeader {
    pub fn new(key: String) -> Self {
        MissingHeader { key }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for MissingHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.key)
    }
}

impl std::error::Error for MissingHeader {}

#[derive(Debug, Serialize)]
pub struct MalformedHeader {
    key: String,
    #[serde(skip_serializing)]
    source: ToStrError,
}

impl MalformedHeader {
    pub fn new(key: String, source: ToStrError) -> Self {
        MalformedHeader { key, source }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for MalformedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.key)
    }
}

impl std::error::Error for MalformedHeader {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Serialize)]
pub struct UnsupportedContentType {
    content_type: String,
}

impl UnsupportedContentType {
    pub fn new(content_type: String) -> Self {
        UnsupportedContentType { content_type }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for UnsupportedContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.content_type)
    }
}

impl std::error::Error for UnsupportedContentType {}

#[derive(Debug, Serialize)]
pub struct InvalidUserAgent {
    user_agent: String,
}

impl InvalidUserAgent {
    pub fn new(user_agent: String) -> Self {
        InvalidUserAgent { user_agent }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for InvalidUserAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.user_agent)
    }
}

impl std::error::Error for InvalidUserAgent {}

#[derive(Debug, Serialize)]
pub struct SignatureMismatch {
    signature: String,
}

impl SignatureMismatch {
    pub fn new(signature: String) -> Self {
        SignatureMismatch { signature }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for SignatureMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.signature)
    }
}

impl std::error::Error for SignatureMismatch {}

#[derive(Debug, Serialize)]
pub struct JsonError {
    #[serde(skip_serializing)]
    source: JsonRejection,
}

impl JsonError {
    pub fn new(source: JsonRejection) -> Self {
        JsonError { source }
    }
    pub fn status(&self) -> StatusCode {
        self.source.status()
    }
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for JsonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
