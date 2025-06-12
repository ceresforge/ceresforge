use axum::{
    Router,
    response::{Html, IntoResponse},
    routing::get,
};
use serde::Serialize;

#[derive(Serialize, Debug)]
#[serde(rename = "md:EntityDescriptor")]
struct EntityDescriptor {
    #[serde(rename = "@xmlns:md")]
    xmlns_md: String,

    #[serde(rename = "@xmlns:saml")]
    xmlns_saml: String,

    #[serde(rename = "@entityID")]
    entity_id: String,
}

async fn acs() -> Html<&'static str> {
    Html("ACS")
}

async fn metadata() -> impl IntoResponse {
    let _enity_descriptor = EntityDescriptor {
        xmlns_md: "urn:oasis:names:tc:SAML:2.0:metadata".to_string(),
        xmlns_saml: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        entity_id: "https://ece.gg/auth/saml/metadata".to_string(),
    };
    Html("Metadata")
}

pub fn routes() -> Router {
    Router::new()
        .route("/saml/acs", get(acs))
        .route("/saml/metadata", get(metadata))
}
