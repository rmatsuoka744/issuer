use crate::config;
use crate::models::{CredentialRequest, Proof, SDJWTVerifiableCredential, TokenResponse};
use crate::user_data::USER_DATA;
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// テスト用の関数
pub fn generate_test_access_token() -> String {
    info!("Generate test access token");
    let expiration = Utc::now() + Duration::hours(1);
    let claims = serde_json::json!({
        "sub": "test_user",
        "scope": "credential_issue",
        "exp": expiration.timestamp()
    });
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config::ACCESS_TOKEN_SECRET.as_ref()),
    )
    .expect("Failed to generate test access token")
}

pub fn generate_test_proof_jwt() -> String {
    info!("Generate test proof jwt");
    let expiration = Utc::now() + Duration::hours(1);
    let claims = serde_json::json!({
        "nonce": "test_nonce",
        "iat": Utc::now().timestamp(),
        "exp": expiration.timestamp()
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config::CLIENT_SECRET.as_ref()),
    )
    .expect("Failed to generate test proof JWT")
}

// 検証関数
pub fn validate_access_token(token: &str) -> bool {
    info!("Validating access token");
    let decoding_key = DecodingKey::from_secret(config::ACCESS_TOKEN_SECRET.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    match decode::<Value>(token, &decoding_key, &validation) {
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
    if req.formats.is_empty() {
        error!("No credential formats specified");
        return false;
    }
    for format in &req.formats {
        if !["jwt_vc_json", "ldp_vc", "sd_jwt_vc"].contains(&format.as_str()) {
            error!("Unsupported credential format: {}", format);
            return false;
        }
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

pub fn verify_proof_of_possession(proof: &Proof, client_secret: &str) -> bool {
    info!("Verifying proof of possession");
    match verify_jwt_with_key(&proof.jwt, client_secret) {
        Ok(claims) => {
            debug!("Proof JWT successfully verified: {:?}", claims);
            if let Some(nonce) = claims.get("nonce") {
                if verify_nonce(nonce.as_str().unwrap_or("")) {
                    info!("Proof of possession verification successful");
                    return true;
                }
            }
            error!("Invalid or missing nonce in proof");
            false
        }
        Err(err) => {
            error!("Proof JWT verification failed: {}", err);
            false
        }
    }
}

// JWT関連の関数
fn generate_jwt(claims: &Value) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(config::CREDENTIAL_SECRET.as_ref()),
    )
    .expect("Failed to encode JWT")
}

// JWT検証用
fn verify_jwt_with_key(token: &str, client_secret: &str) -> Result<Value, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(client_secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Value>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

// クレデンシャル生成関数
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
            "credentialSubject": USER_DATA.clone(),
        }
    });

    let jwt = generate_jwt(&credential);
    info!("Credential generated successfully");
    jwt
}

// ノンス関連の関数
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

// SD-JWT関連の関数
pub fn generate_sd_jwt_vc(req: &CredentialRequest) -> Result<SDJWTVerifiableCredential, String> {
    info!("Generating SD-JWT VC");
    let now = Utc::now();
    let mut claims = serde_json::json!({
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
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
            }
        },
        "_sd_alg": "sha-256",
        "cnf": {
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
            }
        }
    });

    // USER_DATAからクレームを追加
    let selective_claims: Vec<(&str, serde_json::Value)> = USER_DATA
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k != "vct") // vctは除外
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();

    let (_sd_jwt, disclosures, sd_hashes) = generate_sd_jwt(&claims, &selective_claims)?;
    claims["_sd"] = serde_json::Value::Array(sd_hashes);

    // vctをcredentialSubjectに追加
    if let Some(vct) = USER_DATA.get("vct") {
        claims["vc"]["credentialSubject"]["vct"] = vct.clone();
    }

    let key_binding_jwt = generate_key_binding_jwt();

    let header = Header {
        typ: Some("vc+sd-jwt".to_string()),
        alg: Algorithm::HS256,
        ..Default::default()
    };

    let sd_jwt = encode(&header, &claims, &EncodingKey::from_secret(config::CREDENTIAL_SECRET.as_ref()))
        .map_err(|e| e.to_string())?;

    // SD-JWT-VCの検証
    match verify_sd_jwt(&sd_jwt) {
        Ok(_) => {
            Ok(SDJWTVerifiableCredential {
                sd_jwt,
                disclosures,
                key_binding_jwt: Some(key_binding_jwt),
            })
        },
        Err(err) => {
            error!("SD-JWT-VC verification failed: {}", err);
            Err(err)
        }
    }
}

fn generate_sd_jwt(claims: &Value, selective_claims: &[(&str, serde_json::Value)]) -> Result<(String, Vec<String>, Vec<Value>), String> {
    let mut jwt_claims = claims.clone();
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (key, value) in selective_claims {
        let salt = generate_salt();
        let disclosure = format!("[{}, {}, {}]", salt, key, value);
        let encoded_disclosure = general_purpose::URL_SAFE_NO_PAD.encode(&disclosure);
        let hash = hash_disclosure(&disclosure);
        jwt_claims["vc"]["credentialSubject"][key] = Value::String(hash.clone());
        disclosures.push(encoded_disclosure);
        sd_hashes.push(Value::String(hash));
    }

    Ok((jwt_claims.to_string(), disclosures, sd_hashes))
}

fn generate_key_binding_jwt() -> String {
    let claims = serde_json::json!({
        "iat": Utc::now().timestamp(),
        "nonce": generate_salt(),
    });
    generate_jwt(&claims)
}

fn generate_salt() -> String {
    Uuid::new_v4().to_string()
}

fn hash_disclosure(disclosure: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(disclosure);
    let result = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

pub fn verify_sd_jwt(sd_jwt: &str) -> Result<Value, String> {
    info!("Verify SD-JWT");
    let parts: Vec<&str> = sd_jwt.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid SD-JWT format".to_string());
    }
    let jwt = parts[0..3].join(".");
    let disclosures = &parts[3..];
    let mut claims = verify_jwt_with_key(&jwt, config::CREDENTIAL_SECRET).map_err(|e| e.to_string())?;
    for disclosure in disclosures {
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(disclosure)
            .map_err(|_| "Invalid disclosure encoding".to_string())?;
        let disclosure_json: Value = serde_json::from_slice(&decoded)
            .map_err(|_| "Invalid disclosure format".to_string())?;
        if let (Some(_salt), Some(key), Some(value)) = (
            disclosure_json.get(0),
            disclosure_json.get(1),
            disclosure_json.get(2),
        ) {
            let hash = hash_disclosure(disclosure);
            if claims[key.as_str().unwrap()] == Value::String(hash) {
                claims[key.as_str().unwrap()] = value.clone();
            }
        }
    }
    Ok(claims)
}


// TokenEndpoint
pub fn authenticate_client(client_id: &str, client_secret: &str) -> bool {
    if let Some(expected_secret) = config::get_client_secret(client_id) {
        client_secret == expected_secret
    } else {
        false
    }
}

pub fn validate_grant_type(grant_type: &str) -> bool {
    grant_type == "client_credentials"
}

pub fn generate_access_token(client_id: &str, scope: Option<&str>) -> Result<TokenResponse, String> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let scope = scope.unwrap_or("credential_issue").to_string();

    let claims = serde_json::json!({
        "iss": "https://example.com",
        "sub": client_id,
        "aud": "https://api.example.com",
        "exp": (now + expires_in).timestamp(),
        "iat": now.timestamp(),
        "scope": scope,
    });

    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config::ACCESS_TOKEN_SECRET.as_ref())
    ).map_err(|e| e.to_string())?;

    debug!("Access Token: {}", access_token);

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: expires_in.num_seconds() as u64,
        scope,
        c_nonce: Uuid::new_v4().to_string(),
        c_nonce_expires_in: 300, // 5分
    })
}