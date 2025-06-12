use axum::{
    extract::rejection::JsonRejection,
    http::{StatusCode, header::ToStrError},
};
use serde::{Serialize, Serializer};
use std::error::Error;

fn error_serialize<S>(err: &impl Error, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    format!("{}", err).serialize(s)
}

#[derive(Debug, Serialize)]
#[non_exhaustive]
#[serde(tag = "type")]
pub enum ApiError {
    InternalError(InternalError),
    ResourceNotFound(ResourceNotFound),
    MethodNotAllowed(MethodNotAllowed),
    MissingHeader(MissingHeader),
    MalformedHeader(MalformedHeader),
    UnsupportedMediaType(UnsupportedMediaType),
    UnsupportedUserAgent(UnsupportedUserAgent),
    MismatchedSignature(MismatchedSignature),
    UnsupportedWebhookEvent(UnsupportedWebhookEvent),
    JsonError(JsonError),
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::InternalError(err) => err.status(),
            ApiError::ResourceNotFound(err) => err.status(),
            ApiError::MethodNotAllowed(err) => err.status(),
            ApiError::MissingHeader(err) => err.status(),
            ApiError::MalformedHeader(err) => err.status(),
            ApiError::UnsupportedMediaType(err) => err.status(),
            ApiError::UnsupportedUserAgent(err) => err.status(),
            ApiError::MismatchedSignature(err) => err.status(),
            ApiError::UnsupportedWebhookEvent(err) => err.status(),
            ApiError::JsonError(err) => err.status(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            ApiError::InternalError(err) => write!(f, "{err}"),
            ApiError::ResourceNotFound(err) => write!(f, "{err}"),
            ApiError::MethodNotAllowed(err) => write!(f, "{err}"),
            ApiError::MissingHeader(err) => write!(f, "{err}"),
            ApiError::MalformedHeader(err) => write!(f, "{err}"),
            ApiError::UnsupportedMediaType(err) => write!(f, "{err}"),
            ApiError::UnsupportedUserAgent(err) => write!(f, "{err}"),
            ApiError::MismatchedSignature(err) => write!(f, "{err}"),
            ApiError::UnsupportedWebhookEvent(err) => write!(f, "{err}"),
            ApiError::JsonError(err) => write!(f, "{err}"),
        }
    }
}

impl Error for ApiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ApiError::InternalError(err) => err.source(),
            ApiError::ResourceNotFound(err) => err.source(),
            ApiError::MethodNotAllowed(err) => err.source(),
            ApiError::MissingHeader(err) => err.source(),
            ApiError::MalformedHeader(err) => err.source(),
            ApiError::UnsupportedMediaType(err) => err.source(),
            ApiError::UnsupportedUserAgent(err) => err.source(),
            ApiError::MismatchedSignature(err) => err.source(),
            ApiError::UnsupportedWebhookEvent(err) => err.source(),
            ApiError::JsonError(err) => err.source(),
        }
    }
}

impl From<hmac::digest::InvalidLength> for ApiError {
    fn from(err: hmac::digest::InvalidLength) -> ApiError {
        ApiError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<std::env::VarError> for ApiError {
    fn from(err: std::env::VarError) -> ApiError {
        ApiError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<axum::http::Error> for ApiError {
    fn from(err: axum::http::Error) -> ApiError {
        ApiError::InternalError(InternalError::new(Box::new(err)))
    }
}

impl From<ResourceNotFound> for ApiError {
    fn from(err: ResourceNotFound) -> ApiError {
        ApiError::ResourceNotFound(err)
    }
}

impl From<MethodNotAllowed> for ApiError {
    fn from(err: MethodNotAllowed) -> ApiError {
        ApiError::MethodNotAllowed(err)
    }
}

impl From<MissingHeader> for ApiError {
    fn from(err: MissingHeader) -> ApiError {
        ApiError::MissingHeader(err)
    }
}

impl From<MalformedHeader> for ApiError {
    fn from(err: MalformedHeader) -> ApiError {
        ApiError::MalformedHeader(err)
    }
}

impl From<UnsupportedMediaType> for ApiError {
    fn from(err: UnsupportedMediaType) -> ApiError {
        ApiError::UnsupportedMediaType(err)
    }
}

impl From<UnsupportedUserAgent> for ApiError {
    fn from(err: UnsupportedUserAgent) -> ApiError {
        ApiError::UnsupportedUserAgent(err)
    }
}

impl From<MismatchedSignature> for ApiError {
    fn from(err: MismatchedSignature) -> ApiError {
        ApiError::MismatchedSignature(err)
    }
}

impl From<UnsupportedWebhookEvent> for ApiError {
    fn from(err: UnsupportedWebhookEvent) -> ApiError {
        ApiError::UnsupportedWebhookEvent(err)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(source: JsonRejection) -> ApiError {
        ApiError::JsonError(JsonError::new(source))
    }
}

#[derive(Debug, Serialize)]
pub struct InternalError {
    #[serde(skip_serializing)]
    source: Box<dyn Error>,
}

impl InternalError {
    pub fn new(source: Box<dyn Error>) -> Self {
        InternalError { source }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl Error for InternalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
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

impl Error for ResourceNotFound {}

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

impl Error for MethodNotAllowed {}

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

impl Error for MissingHeader {}

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

impl Error for MalformedHeader {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Serialize)]
pub struct UnsupportedMediaType {
    content_type: String,
}

impl UnsupportedMediaType {
    pub fn new(content_type: String) -> Self {
        UnsupportedMediaType { content_type }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    }
}

impl std::fmt::Display for UnsupportedMediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.content_type)
    }
}

impl Error for UnsupportedMediaType {}

#[derive(Debug, Serialize)]
pub struct UnsupportedUserAgent {
    user_agent: String,
}

impl UnsupportedUserAgent {
    pub fn new(user_agent: String) -> Self {
        UnsupportedUserAgent { user_agent }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for UnsupportedUserAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.user_agent)
    }
}

impl Error for UnsupportedUserAgent {}

#[derive(Debug, Serialize)]
pub struct MismatchedSignature {
    signature: String,
}

impl MismatchedSignature {
    pub fn new(signature: String) -> Self {
        MismatchedSignature { signature }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for MismatchedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.signature)
    }
}

impl Error for MismatchedSignature {}

#[derive(Debug, Serialize)]
pub struct UnsupportedWebhookEvent {
    event: String,
}

impl UnsupportedWebhookEvent {
    pub fn new(event: String) -> Self {
        UnsupportedWebhookEvent { event }
    }
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for UnsupportedWebhookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.event)
    }
}

impl Error for UnsupportedWebhookEvent {}

#[derive(Debug, Serialize)]
pub struct JsonError {
    #[serde(serialize_with = "error_serialize")]
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

impl Error for JsonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
