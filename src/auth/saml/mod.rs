use super::{Params, already_logged_in, create_cookie};
use crate::frontend::FrontendResult;
use crate::record::{SamlAttribute, SamlProvider, User};
use crate::{AppState, base, plain_400, plain_401, plain_404};
use axum::extract::State;
use axum::{
    Router,
    extract::{Form, Path, Query},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::PrivateCookieJar;
use base64ct::{Base64, Encoding};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use maud::html;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Payload {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SamlResponse {
    #[serde(rename = "@Destination")]
    destination: String,

    #[serde(rename = "@ID")]
    id: String,

    #[serde(rename = "@InResponseTo")]
    in_response_to: String,

    #[serde(rename = "@IssueInstant")]
    issue_instant: String,

    #[serde(rename = "@Version")]
    version: String,

    #[serde(rename = "Issuer")]
    issuer: Issuer,

    #[serde(rename = "Signature")]
    signature: Option<Signature>,

    #[serde(rename = "Status")]
    status: Status,

    #[serde(rename = "Assertion")]
    assertion: Assertion,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Issuer {
    #[serde(rename = "$value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Signature {
    #[serde(rename = "SignedInfo")]
    signed_info: SignedInfo,

    #[serde(rename = "SignatureValue")]
    signature_value: SignatureValue,

    #[serde(rename = "KeyInfo")]
    key_info: KeyInfo,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SignedInfo {
    #[serde(rename = "CanonicalizationMethod")]
    canonicalization_method: CanonicalizationMethod,

    #[serde(rename = "SignatureMethod")]
    signature_method: SignatureMethod,

    #[serde(rename = "Reference")]
    reference: Reference,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct CanonicalizationMethod {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SignatureMethod {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Reference {
    #[serde(rename = "@URI")]
    uri: String,

    #[serde(rename = "Transforms")]
    transforms: Transforms,

    #[serde(rename = "DigestMethod")]
    digest_method: DigestMethod,

    #[serde(rename = "DigestValue")]
    digest_value: DigestValue,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Transforms {
    #[serde(rename = "Transform")]
    transforms: Vec<Transform>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Transform {
    #[serde(rename = "@Algorithm")]
    algorithm: String,

    #[serde(rename = "InclusiveNamespaces")]
    inclusive_namespaces: Option<InclusiveNamespaces>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct InclusiveNamespaces {
    #[serde(rename = "@PrefixList")]
    prefix_list: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct DigestMethod {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct DigestValue {
    #[serde(rename = "$value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SignatureValue {
    #[serde(rename = "$value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct KeyInfo {
    #[serde(rename = "X509Data")]
    x509_data: X509Data,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct X509Data {
    #[serde(rename = "X509Certificate")]
    x509_certificate: X509Certificate,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct X509Certificate {
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Status {
    #[serde(rename = "StatusCode")]
    status_code: SamlStatusCode,
}

#[derive(Clone, Debug, Deserialize)]
struct SamlStatusCode {
    #[serde(rename = "@Value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Assertion {
    #[serde(rename = "@ID")]
    id: String,

    #[serde(rename = "@IssueInstant")]
    issue_instant: String,

    #[serde(rename = "@Version")]
    version: String,

    #[serde(rename = "Issuer")]
    issuer: Issuer,

    #[serde(rename = "Subject")]
    subject: Subject,

    #[serde(rename = "Conditions")]
    conditions: Conditions,

    #[serde(rename = "AuthnStatement")]
    authn_statement: AuthnStatement,

    #[serde(rename = "AttributeStatement")]
    attribute_statement: AttributeStatement,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Subject {
    #[serde(rename = "NameID")]
    name_id: NameId,

    #[serde(rename = "SubjectConfirmation")]
    subject_confirmation: SubjectConfirmation,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct NameId {
    #[serde(rename = "@Format")]
    format: String,

    #[serde(rename = "@NameQualifier")]
    name_qualifier: String,

    #[serde(rename = "@SPNameQualifier")]
    sp_name_qualifier: String,

    #[serde(rename = "$value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SubjectConfirmation {
    #[serde(rename = "@Method")]
    method: String,

    #[serde(rename = "SubjectConfirmationData")]
    subject_confirmation_data: SubjectConfirmationData,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SubjectConfirmationData {
    #[serde(rename = "@Address")]
    address: String,

    #[serde(rename = "@InResponseTo")]
    in_response_to: String,

    #[serde(rename = "@NotOnOrAfter")]
    not_on_or_after: String,

    #[serde(rename = "@Recipient")]
    recipient: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Conditions {
    #[serde(rename = "@NotBefore")]
    not_before: String,

    #[serde(rename = "@NotOnOrAfter")]
    not_on_or_after: String,

    #[serde(rename = "AudienceRestriction")]
    audience_restriction: AudienceRestriction,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct AudienceRestriction {
    #[serde(rename = "Audience")]
    audience: Audience,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Audience {
    #[serde(rename = "$value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct AuthnStatement {
    #[serde(rename = "@AuthnInstant")]
    authn_instant: String,

    #[serde(rename = "@SessionIndex")]
    session_index: String,

    #[serde(rename = "SubjectLocality")]
    subject_locality: SubjectLocality,

    #[serde(rename = "AuthnContext")]
    authn_context: AuthnContext,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SubjectLocality {
    #[serde(rename = "@Address")]
    address: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct AuthnContext {
    #[serde(rename = "AuthnContextClassRef")]
    authn_context_class_ref: AuthnContextClassRef,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct AuthnContextClassRef {
    #[serde(rename = "$value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct AttributeStatement {
    #[serde(rename = "Attribute")]
    attributes: Vec<Attribute>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Attribute {
    #[serde(rename = "@FriendlyName")]
    friendly_name: String,

    #[serde(rename = "@Name")]
    name: String,

    #[serde(rename = "@NameFormat")]
    name_format: String,

    #[serde(rename = "AttributeValue")]
    attribute_value: AttributeValue,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct AttributeValue {
    #[serde(rename = "NameID")]
    name_id: Option<NameId>,

    #[serde(rename = "$value")]
    value: Option<String>,
}

impl ToString for AttributeValue {
    fn to_string(&self) -> String {
        if let Some(name_id) = &self.name_id {
            return name_id.value.to_string();
        }
        if let Some(value) = &self.value {
            return value.to_string();
        }
        panic!()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename = "samlp:AuthnRequest")]
struct AuthnRequest {
    #[serde(rename = "@xmlns:saml")]
    xmlns_saml: String,

    #[serde(rename = "@xmlns:samlp")]
    xmlns_samlp: String,

    #[serde(rename = "@ID")]
    id: String,

    #[serde(rename = "@Version")]
    version: String,

    #[serde(rename = "@IssueInstant")]
    issue_instant: String,

    #[serde(rename = "@Destination")]
    destination: String,

    #[serde(rename = "@AssertionConsumerServiceURL")]
    assertion_consumer_service_url: String,

    #[serde(rename = "saml:Issuer")]
    issuer: String,

    #[serde(rename = "samlp:NameIDPolicy")]
    name_id_policy: NameIdPolicy,
}

#[derive(Debug, Serialize)]
struct NameIdPolicy {
    #[serde(rename = "@AllowCreate")]
    allow_create: String,

    #[serde(rename = "@Format")]
    format: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "md:EntityDescriptor")]
struct EntityDescriptor {
    #[serde(rename = "@xmlns:md")]
    xmlns_md: String,

    #[serde(rename = "@xmlns:saml")]
    xmlns_saml: String,

    #[serde(rename = "@ID")]
    id: String,

    #[serde(rename = "@entityID")]
    entity_id: String,

    #[serde(rename = "md:SPSSODescriptor")]
    sp_sso_descriptor: SPSSODescriptor,
}

#[derive(Debug, Deserialize, Serialize)]
struct SPSSODescriptor {
    #[serde(rename = "@AuthnRequestsSigned")]
    authn_requests_signed: String,

    #[serde(rename = "@WantAssertionsSigned")]
    want_assertions_signed: String,

    #[serde(rename = "@protocolSupportEnumeration")]
    protocol_support_enumeration: String,

    #[serde(rename = "md:NameIDFormat")]
    name_id_format: String,

    #[serde(rename = "md:AssertionConsumerService")]
    assertion_consumer_service: AssertionConsumerService,

    #[serde(rename = "md:AttributeConsumingService")]
    attribute_consuming_services: Vec<AttributeConsumingService>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AssertionConsumerService {
    #[serde(rename = "@Binding")]
    binding: String,

    #[serde(rename = "@Location")]
    location: String,

    #[serde(rename = "@index")]
    index: String,

    #[serde(rename = "@isDefault")]
    is_default: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttributeConsumingService {
    #[serde(rename = "@index")]
    index: String,

    #[serde(rename = "@isDefault")]
    is_default: String,

    #[serde(rename = "md:ServiceName")]
    service_name: ServiceName,

    #[serde(rename = "md:RequestedAttribute")]
    requested_attributes: Vec<RequestedAttribute>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ServiceName {
    #[serde(rename = "@xml:lang")]
    lang: String,

    #[serde(rename = "$value")]
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RequestedAttribute {
    #[serde(rename = "@FriendlyName")]
    friendly_name: String,

    #[serde(rename = "@Name")]
    name: String,

    #[serde(rename = "@NameFormat")]
    name_format: String,

    #[serde(rename = "@isRequired")]
    is_required: String,
}

fn is_valid_slug(s: &str) -> bool {
    s.len() >= 3
        && s.len() < 32
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

async fn get_saml_provider(provider: &str, pool: &PgPool) -> FrontendResult<Option<SamlProvider>> {
    if !is_valid_slug(provider) {
        return Ok(None);
    }
    Ok(sqlx::query_as!(
        SamlProvider,
        r#"
        SELECT * FROM auth_saml_providers WHERE slug = $1
        "#,
        provider
    )
    .fetch_optional(pool)
    .await?)
}

fn transform_attributes(attribute_statement: &AttributeStatement) -> Vec<SamlAttribute> {
    attribute_statement
        .attributes
        .iter()
        .map(|a| SamlAttribute {
            friendly_name: a.friendly_name.clone(),
            name: a.name.clone(),
            name_format: a.name_format.clone(),
            value: a.attribute_value.to_string(),
        })
        .collect()
}

fn already_connected() -> Response {
    let title = "Connect";
    let description = "Already connected.";
    html! {
        (base(&title, description, html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p .warning {
                    (description)
                }
            }
        }))
    }
    .into_response()
}

fn already_connected_to_different_name_id() -> Response {
    let title = "Connect";
    let description =
        "Your account is already connected to a different identity from this provider.";
    html! {
        (base(&title, description, html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p .warning {
                    (description)
                }
            }
        }))
    }
    .into_response()
}

fn not_connected() -> Response {
    let title = "Login";
    let description = "Not connected.";
    html! {
        (base(&title, description, html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p .warning {
                    (description)
                }
            }
        }))
    }
    .into_response()
}

async fn verify_response(provider: &SamlProvider, xml: &str) -> Result<bool, std::io::Error> {
    let pem_path = get_pem(provider).await;

    let mut child = Command::new("xmlsec1")
        .arg("--verify")
        .arg("--id-attr:ID")
        .arg("Response")
        .arg("--trusted-pem")
        .arg(pem_path)
        .arg("/dev/stdin")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(xml.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().unwrap();
    Ok(output.status.success())
}

async fn update_credentials(
    pool: &PgPool,
    user_id: i64,
    provider_id: i64,
    name_id: &str,
    attributes_json: &serde_json::Value,
) -> FrontendResult<()> {
    sqlx::query!(
        r#"
        UPDATE auth_saml_provider_credentials
        SET attributes = $1, updated_at = now()
        WHERE user_id = $2
            AND provider_id = $3
            AND name_id = $4
        "#,
        attributes_json,
        user_id,
        provider_id,
        name_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename = "md:EntityDescriptor")]
struct ProviderEntityDescriptor {
    #[serde(rename = "@xmlns:md")]
    xmlns_md: String,

    #[serde(rename = "@xmlns:saml")]
    xmlns_saml: String,

    #[serde(rename = "@entityID")]
    entity_id: String,

    #[serde(rename = "IDPSSODescriptor")]
    idp_sso_descriptor: IDPSSODescriptor,
}

#[derive(Debug, Deserialize)]
struct IDPSSODescriptor {
    #[serde(rename = "KeyDescriptor")]
    key_descriptor: KeyDescriptor,
}

#[derive(Debug, Deserialize)]
struct KeyDescriptor {
    #[serde(rename = "KeyInfo")]
    key_info: KeyInfo,
}

fn get_cache_dir() -> Option<PathBuf> {
    if std::process::id() == 0 {
        return Some(PathBuf::from("/var/cache"));
    }
    match std::env::var("XDG_CACHE_HOME") {
        Ok(path_str) if !path_str.is_empty() => Some(PathBuf::from(path_str)),
        _ => match std::env::var("HOME") {
            Ok(home_dir_str) if !home_dir_str.is_empty() => {
                let mut cache_path = PathBuf::from(home_dir_str);
                cache_path.push(".cache");
                Some(cache_path)
            }
            _ => None,
        },
    }
}

async fn get_pem(provider: &SamlProvider) -> PathBuf {
    let metadata_url = &provider.metadata_url;
    let request = reqwest::get(metadata_url)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let entity_descriptor: ProviderEntityDescriptor = quick_xml::de::from_str(&request).unwrap();

    let mut certificate = entity_descriptor
        .idp_sso_descriptor
        .key_descriptor
        .key_info
        .x509_data
        .x509_certificate
        .value;
    certificate.retain(|c| !char::is_whitespace(c));

    let cache_dir = get_cache_dir().unwrap();
    let saml_dir = cache_dir.join("ceresforge/auth/saml");
    std::fs::create_dir_all(&saml_dir).unwrap();
    let pem_path = saml_dir.join(format!("{}.pem", &provider.slug));

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pem_path)
    {
        Ok(mut file) => {
            let pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                certificate
            );
            file.write_all(pem.as_bytes()).unwrap();
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => panic!(),
    }

    pem_path
}

async fn acs(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(provider): Path<String>,
    Form(payload): Form<Payload>,
) -> FrontendResult<Response> {
    let pool = &state.pool;
    let provider = match get_saml_provider(&provider, pool).await? {
        Some(p) => p,
        None => return Ok(plain_404()),
    };

    let saml_response = payload.saml_response;
    let decoded_bytes = Base64::decode_vec(&saml_response)?;
    let xml = String::from_utf8(decoded_bytes)?;

    let is_verified = verify_response(&provider, &xml).await?;
    if !is_verified {
        return Ok(plain_400());
    }

    let response: SamlResponse = quick_xml::de::from_str(&xml)?;

    if response.status.status_code.value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        return Ok(plain_400());
    }
    let uuid_str = match response.in_response_to.strip_prefix('_') {
        Some(s) => s,
        None => return Ok(plain_400()),
    };
    let uuid = match Uuid::from_str(uuid_str) {
        Ok(s) => s,
        Err(_) => return Ok(plain_400()),
    };

    let record = sqlx::query!(
        r#"
        SELECT
            *
        FROM
            auth_saml_provider_requests
        WHERE
            id = $1
            AND expires_at > now()
        "#,
        uuid
    )
    .fetch_optional(pool)
    .await?;

    let request = match record {
        Some(r) => r,
        None => return Ok(plain_400()),
    };
    if request.completed_at.is_some() {
        return Ok(plain_400());
    }
    if request.provider_id != provider.id {
        return Ok(plain_400());
    }
    let redirect = request.redirect.as_deref();

    let name_id = response.assertion.subject.name_id.value;
    let attributes = transform_attributes(&response.assertion.attribute_statement);
    tracing::debug!("attributes = {:#?}", attributes);
    let attributes_json = serde_json::to_value(&attributes)?;
    sqlx::query!(
        r#"
        UPDATE auth_saml_provider_requests
        SET completed_at = now(), name_id = $1, attributes = $2
        WHERE id = $3
        "#,
        name_id,
        attributes_json,
        uuid
    )
    .execute(pool)
    .await?;

    let credential = sqlx::query!(
        r#"
        SELECT user_id
        FROM auth_saml_provider_credentials
        WHERE provider_id = $1 AND name_id = $2
        "#,
        provider.id,
        name_id,
    )
    .fetch_optional(pool)
    .await?;

    match request.user_id {
        /* Connect */
        Some(user_id) => match credential {
            Some(credential) => {
                if user_id != credential.user_id {
                    return Ok(already_connected());
                } else {
                    update_credentials(
                        pool,
                        user_id,
                        provider.id,
                        name_id.as_str(),
                        &attributes_json,
                    )
                    .await?;
                    return Ok(Redirect::to(redirect.unwrap_or("/")).into_response());
                }
            }
            None => {
                let result = sqlx::query!(
                    r#"
                    INSERT INTO
                        auth_saml_provider_credentials
                        (user_id, provider_id, name_id, attributes)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (user_id, provider_id)
                    DO NOTHING
                    "#,
                    user_id,
                    provider.id,
                    name_id,
                    attributes_json
                )
                .execute(pool)
                .await?;
                if result.rows_affected() == 0 {
                    return Ok(already_connected_to_different_name_id());
                }
                Ok(Redirect::to(redirect.unwrap_or("/")).into_response())
            }
        },
        /* Login */
        None => match credential {
            Some(c) => {
                let user_id = c.user_id;
                update_credentials(
                    pool,
                    user_id,
                    provider.id,
                    name_id.as_str(),
                    &attributes_json,
                )
                .await?;
                create_cookie(pool, jar, user_id, redirect).await
            }
            None => {
                if !provider.is_user_creation_allowed {
                    return Ok(not_connected());
                }
                let mapped_attributes: HashMap<String, String> =
                    match serde_json::from_value(provider.mapped_attributes) {
                        Ok(m) => m,
                        Err(_) => return Ok(plain_400()), /* Site admin issue. */
                    };
                let fields: HashMap<String, String> = attributes
                    .iter()
                    .filter_map(|a| {
                        mapped_attributes
                            .get(&a.name)
                            .map(|k| (k.clone(), a.value.clone()))
                    })
                    .collect();
                let username = match fields.get("username") {
                    Some(s) => s.as_str(),
                    None => return Ok(plain_400()), /* Site admin issue. */
                };
                let email = match fields.get("email") {
                    Some(s) => s.as_str(),
                    None => return Ok(plain_400()), /* Site admin issue. */
                };
                let first_name = fields.get("first_name");
                let last_name = fields.get("last_name");
                let user_id = sqlx::query!(
                    r#"
                    INSERT INTO users (username, email, first_name, last_name)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                    "#,
                    username,
                    email,
                    first_name,
                    last_name
                )
                .fetch_one(pool)
                .await?
                .id;

                sqlx::query!(
                    r#"
                    INSERT INTO
                        auth_saml_provider_credentials
                        (user_id, provider_id, name_id, attributes)
                    VALUES ($1, $2, $3, $4)
                    "#,
                    user_id,
                    provider.id,
                    name_id,
                    attributes_json
                )
                .execute(pool)
                .await?;

                create_cookie(pool, jar, user_id, redirect).await
            }
        },
    }
}

async fn create_saml_request(
    pool: &PgPool,
    provider: &SamlProvider,
    user_id: Option<i64>,
    redirect: Option<String>,
) -> FrontendResult<Response> {
    let base_url = std::env::var("BASE_URL")?;
    let entity_id = format!("{}/auth/saml/metadata/{}", &base_url, &provider.slug);
    let assertion_consumer_service_url = format!("{}/auth/saml/acs/{}", &base_url, &provider.slug);
    let destination = provider.sso_url.clone();

    let name_id_policy = NameIdPolicy {
        allow_create: "true".to_string(),
        format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string(),
    };
    let uuid = uuid::Uuid::new_v4();
    let authn_request = AuthnRequest {
        xmlns_saml: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        xmlns_samlp: "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        id: format!("_{}", uuid.to_string()),
        version: "2.0".to_string(),
        issue_instant: OffsetDateTime::now_utc()
            .replace_nanosecond(0)?
            .format(&Rfc3339)?,
        destination: destination.clone(),
        assertion_consumer_service_url: assertion_consumer_service_url,
        issuer: entity_id,
        name_id_policy,
    };
    let xml = quick_xml::se::to_string(&authn_request)?;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes())?;
    let bytes = encoder.finish()?;
    let encoded = Base64::encode_string(&bytes);
    let uri = format!(
        "{}?SAMLRequest={}",
        &destination,
        urlencoding::encode(&encoded)
    );
    sqlx::query!(
        r#"
        INSERT INTO auth_saml_provider_requests (id, user_id, provider_id, redirect)
        VALUES ($1, $2, $3, $4)
        "#,
        uuid,
        user_id,
        provider.id,
        redirect,
    )
    .execute(pool)
    .await?;
    Ok(Redirect::to(&uri).into_response())
}

async fn login(
    State(state): State<AppState>,
    user: Option<User>,
    Query(params): Query<Params>,
    Path(provider): Path<String>,
) -> FrontendResult<Response> {
    let pool = &state.pool;
    let provider = match get_saml_provider(&provider, pool).await? {
        Some(p) => p,
        None => return Ok(plain_404()),
    };
    if user.is_some() {
        return Ok(already_logged_in());
    }
    let user_id = user.map(|u| u.id);
    create_saml_request(pool, &provider, user_id, params.redirect).await
}

async fn connect(
    State(state): State<AppState>,
    user: Option<User>,
    Query(params): Query<Params>,
    Path(provider): Path<String>,
) -> FrontendResult<Response> {
    let pool = &state.pool;
    let provider = match get_saml_provider(&provider, pool).await? {
        Some(p) => p,
        None => return Ok(plain_404()),
    };
    if user.is_none() {
        return Ok(plain_401());
    }
    let user_id = user.map(|u| u.id);
    create_saml_request(pool, &provider, user_id, params.redirect).await
}

async fn metadata(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> FrontendResult<Response> {
    let pool = &state.pool;
    let provider = match get_saml_provider(&provider, pool).await? {
        Some(p) => p,
        None => return Ok(plain_404()),
    };

    let base_url = std::env::var("BASE_URL")?;
    let entity_id = format!("{}/auth/saml/metadata/{}", &base_url, &provider.slug);
    let acs_location = format!("{}/auth/saml/acs/{}", &base_url, &provider.slug);

    let requested_attributes = match provider.requested_attributes.as_array() {
        Some(v) => v,
        None => return Ok(plain_400()), /* Site admin issue. */
    };

    let mut entity_descriptor = EntityDescriptor {
        xmlns_md: "urn:oasis:names:tc:SAML:2.0:metadata".to_string(),
        xmlns_saml: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        id: format!("_{}", uuid::Uuid::new_v4().to_string()),
        entity_id: entity_id,
        sp_sso_descriptor: SPSSODescriptor {
            authn_requests_signed: "false".to_string(),
            want_assertions_signed: "false".to_string(),
            protocol_support_enumeration: "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string(),
            assertion_consumer_service: AssertionConsumerService {
                binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
                location: acs_location,
                index: "0".to_string(),
                is_default: "true".to_string(),
            },
            attribute_consuming_services: vec![AttributeConsumingService {
                index: "1".to_string(),
                is_default: "true".to_string(),
                service_name: ServiceName {
                    lang: "en".to_string(),
                    value: "Required attributes".to_string(),
                },
                requested_attributes: vec![],
            }],
        },
    };
    for attribute_consuming_service in &mut entity_descriptor
        .sp_sso_descriptor
        .attribute_consuming_services
    {
        for requested_attribute in requested_attributes {
            attribute_consuming_service
                .requested_attributes
                .push(RequestedAttribute {
                    friendly_name: requested_attribute
                        .get("friendly_name")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                    name: requested_attribute
                        .get("name")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                    name_format: requested_attribute
                        .get("name_format")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                    is_required: requested_attribute
                        .get("is_required")
                        .unwrap()
                        .as_bool()
                        .unwrap()
                        .to_string(),
                });
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/xml".parse()?);

    Ok((
        StatusCode::OK,
        headers,
        quick_xml::se::to_string(&entity_descriptor)?,
    )
        .into_response())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login/{provider}", get(login))
        .route("/connect/{provider}", get(connect))
        .route("/acs/{provider}", post(acs))
        .route("/metadata/{provider}", get(metadata))
}
