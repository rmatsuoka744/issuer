use crate::config;
use crate::models::{CredentialRequest, Proof};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info};
use uuid::Uuid;

// テスト用のアクセストークン、JWTを生成する関数
pub fn generate_test_access_token() -> String {
    let expiration = Utc::now() + Duration::hours(1);
    let claims = serde_json::json!({
        "sub": "test_user",
        "scope": "credential_issue",
        "exp": expiration.timestamp()
    });

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(crate::config::JWT_SECRET.as_ref()),
    )
    .expect("Failed to generate test access token")
}

pub fn generate_test_proof_jwt() -> String {
    let expiration = Utc::now() + Duration::hours(1);
    let claims = serde_json::json!({
        "nonce": "test_nonce",
        "iat": Utc::now().timestamp(),
        "exp": expiration.timestamp()
    });

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config::JWT_SECRET.as_ref()),
    )
    .expect("Failed to generate test proof JWT")
}

pub fn validate_access_token(token: &str) -> bool {
    info!("Validating access token");
    let decoding_key = DecodingKey::from_secret(config::JWT_SECRET.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    match decode::<serde_json::Value>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            debug!("Token successfully decoded: {:?}", token_data.claims);
            if let Some(scope) = token_data.claims.get("scope") {
                if scope.as_str().unwrap_or("").contains("credential_issue") {
                    info!("Access token validation successful");
                    return true;
                }
            }
            error!("Token does not have required scope");
            false
        }
        Err(err) => {
            error!("Token validation failed: {}", err);
            false
        }
    }
}

pub fn validate_request(req: &CredentialRequest) -> bool {
    info!("Validating request");
    if !["jwt_vc_json", "ldp_vc"].contains(&req.format.as_str()) {
        error!("Unsupported credential format: {}", req.format);
        return false;
    }
    if !req.types.contains(&"VerifiableCredential".to_string()) {
        error!("VerifiableCredential type is missing");
        return false;
    }
    if req.proof.proof_type != "jwt" {
        error!("Unsupported proof type: {}", req.proof.proof_type);
        return false;
    }
    info!("Request validation successful");
    true
}

pub fn verify_proof_of_possession(proof: &Proof) -> bool {
    info!("Verifying proof of possession");
    let decoding_key = DecodingKey::from_secret(config::JWT_SECRET.as_ref());
    let mut validation = Validation::new(Algorithm::HS256); // ES256からHS256に変更
    validation.validate_exp = false;

    match decode::<serde_json::Value>(&proof.jwt, &decoding_key, &validation) {
        Ok(token_data) => {
            debug!("Proof JWT successfully decoded: {:?}", token_data.claims);
            if let Some(nonce) = token_data.claims.get("nonce") {
                if verify_nonce(nonce.as_str().unwrap_or("")) {
                    info!("Proof of possession verification successful");
                    return true;
                }
            }
            error!("Invalid or missing nonce in proof");
            false
        }
        Err(err) => {
            error!("Proof JWT validation failed: {}", err);
            false
        }
    }
}

pub fn generate_credential(req: &CredentialRequest) -> String {
    info!("Generating credential");
    let now = Utc::now();
    let credential = serde_json::json!({
        "iss": config::CREDENTIAL_ISSUER,
        "sub": Uuid::new_v4().to_string(),
        "iat": now.timestamp(),
        "exp": (now + Duration::hours(24)).timestamp(),
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": req.types.clone(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                // 実際のクレデンシャルデータをここに追加
            }
        }
    });

    let encoded = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(Algorithm::HS256),
        &credential,
        &jsonwebtoken::EncodingKey::from_secret(config::JWT_SECRET.as_ref()),
    )
    .expect("Failed to encode credential");

    info!("Credential generated successfully");
    encoded
}

pub fn generate_nonce() -> (String, u64) {
    info!("Generating nonce");
    let nonce = Uuid::new_v4().to_string();
    let expires_in = config::NONCE_EXPIRATION;
    store_nonce(&nonce, expires_in);
    info!("Nonce generated successfully");
    (nonce, expires_in)
}

fn verify_nonce(_nonce: &str) -> bool {
    // 実際の実装ではストレージからノンスを取得し、有効期限を確認
    true
}

fn store_nonce(nonce: &str, _expires_in: u64) {
    debug!("Storing nonce: {}", nonce);
    // 実際の実装ではデータベースなどにノンスを保存
}
