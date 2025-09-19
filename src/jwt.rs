use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use time::{OffsetDateTime, Duration};

use crate::AppState;

#[derive(Debug, Serialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, Serialize)]
struct Payload {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Debug, Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Serialize)]
struct Jwk {
    kty: &'static str,
    #[serde(rename = "use")]
    key_use: &'static str,
    alg: &'static str,
    kid: String,
    n: String,
    e: String,
}

pub fn calculate_jwk_thumbprint(public_key: &RsaPublicKey) -> String {
    let n = public_key.n().to_be_bytes_trimmed_vartime();
    let n = base64ct::Base64UrlUnpadded::encode_string(&n);
    let e = public_key.e().to_be_bytes_trimmed_vartime();
    let e = base64ct::Base64UrlUnpadded::encode_string(&e);

    // This is the required order for RSA public keys
    let mut canonical_jwk = std::collections::BTreeMap::new();
    canonical_jwk.insert("e", e);
    canonical_jwk.insert("kty", "RSA".to_string());
    canonical_jwk.insert("n", n);

    let canonical_json = serde_json::to_string(&canonical_jwk).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let hash_digest = hasher.finalize();

    let thumbprint = Base64UrlUnpadded::encode_string(&hash_digest);

    thumbprint
}

pub async fn jwks_handler(State(state): State<AppState>) -> impl IntoResponse {
    let private_key = state.jwt_rsa_key;
    let public_key = RsaPublicKey::from(&private_key);
    
    let kid = calculate_jwk_thumbprint(&public_key);
    let n = public_key.n().to_be_bytes_trimmed_vartime();
    let n = base64ct::Base64UrlUnpadded::encode_string(&n);
    let e = public_key.e().to_be_bytes_trimmed_vartime();
    let e = base64ct::Base64UrlUnpadded::encode_string(&e);

    let jwks = Jwks {
        keys: vec![Jwk{
            kty: "RSA",
            key_use: "sig",
            alg: "RS256",
            kid,
            n,
            e,
        }]
    };
    
    Json(jwks)
}


pub fn generate_id_token(private_key: &RsaPrivateKey, user_id: i64, client_id: &str) -> String {
    let public_key = RsaPublicKey::from(private_key);
    let kid = calculate_jwk_thumbprint(&public_key);

    let header = Header {
        alg: "RS256".to_string(),
        typ: "JWT".to_string(),
        kid: kid.clone(),
    };

    let iss = std::env::var("BASE_URL").unwrap();
    let sub = user_id.to_string();
    let aud = client_id.to_string();

    let now = OffsetDateTime::now_utc();
    let iat = now.unix_timestamp();
    let expiration_time: OffsetDateTime = now + Duration::minutes(10);
    let exp = expiration_time.unix_timestamp();

    let payload = Payload {
        iss,
        sub,
        aud,
        iat,
        exp,
    };

    generate_jwt(&header, &payload, private_key)
}

// async fn generate_jwt() -> String {
fn generate_jwt(header: &Header, payload: &Payload, private_key: &RsaPrivateKey) -> String {
    let header = serde_json::to_string(header).unwrap();
    let header = Base64UrlUnpadded::encode_string(header.as_bytes());
    let payload = serde_json::to_string(payload).unwrap();
    let payload = Base64UrlUnpadded::encode_string(payload.as_bytes());
    let unsigned = format!("{}.{}", header, payload);

    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let mut rng = rand::rng();
    let signature = signing_key.sign_with_rng(&mut rng, unsigned.as_bytes());
    let signature = Base64UrlUnpadded::encode_string(&signature.to_vec());
    
    format!("{}.{}", unsigned, signature)
}
