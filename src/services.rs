use crate::config;
use crate::db::{get_client_secret_by_id, get_private_key_as_str, get_public_key_as_str};
use crate::errors::IssuerError;
use crate::models::{CredentialRequest, Proof, SDJWTVerifiableCredential, TokenResponse};
use crate::user_data::USER_DATA;
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// キー取得のヘルパー関数
fn get_encoding_key(key_type: &str) -> Result<EncodingKey, IssuerError> {
    let private_key = get_private_key_as_str(key_type)
        .map_err(|_| IssuerError::PrivateKeyLoadError(key_type.to_string()))?;
    EncodingKey::from_ed_pem(private_key.as_ref()).map_err(|_| IssuerError::InvalidPrivateKeyFormat)
}

fn get_decoding_key(key_type: &str) -> Result<DecodingKey, IssuerError> {
    let public_key = get_public_key_as_str(key_type)
        .map_err(|_| IssuerError::PublicKeyLoadError(key_type.to_string()))?;
    DecodingKey::from_ed_pem(public_key.as_ref()).map_err(|_| IssuerError::InvalidPublicKeyFormat)
}

// テスト用のJWT生成関数
pub fn generate_test_access_token() -> Result<String, IssuerError> {
    info!("Generate test access token");
    let expiration = Utc::now() + Duration::hours(1);
    let claims = serde_json::json!({
        "sub": "test_user",
        "scope": "credential_issue",
        "exp": expiration.timestamp()
    });
    let encoding_key = get_encoding_key("ACCESS_TOKEN")?;
    generate_jwt(&claims, &encoding_key, None)
}

pub fn generate_test_proof_jwt() -> Result<String, IssuerError> {
    info!("Generate test proof jwt");
    let expiration = Utc::now() + Duration::hours(1);
    let claims = serde_json::json!({
        "nonce": "test_nonce",
        "iat": Utc::now().timestamp(),
        "exp": expiration.timestamp()
    });
    let encoding_key = get_encoding_key("CLIENT_AUTH")?;
    generate_jwt(&claims, &encoding_key, None)
}

// JWT生成の共通関数
fn generate_jwt(
    claims: &Value,
    encoding_key: &EncodingKey,
    header: Option<Header>,
) -> Result<String, IssuerError> {
    let header = header.unwrap_or_else(|| Header::new(Algorithm::EdDSA));
    encode(&header, claims, encoding_key).map_err(|e| IssuerError::JwtEncodingError(e.to_string()))
}

// JWT検証の共通関数
fn verify_jwt_with_key(token: &str, decoding_key: &DecodingKey) -> Result<Value, IssuerError> {
    let validation = Validation::new(Algorithm::EdDSA);
    let token_data = decode::<Value>(token, decoding_key, &validation)
        .map_err(|e| IssuerError::JwtDecodingError(e.to_string()))?;
    Ok(token_data.claims)
}

// アクセストークンの検証関数
pub fn validate_access_token(token: &str) -> Result<(), IssuerError> {
    info!("Validating access token");
    let decoding_key = get_decoding_key("ACCESS_TOKEN")?;
    let token_data = verify_jwt_with_key(token, &decoding_key)?;
    debug!("Token successfully decoded: {:?}", token_data);

    let scope = token_data
        .get("scope")
        .and_then(|s| s.as_str())
        .ok_or(IssuerError::MissingScopeClaim)?;

    if scope.contains("credential_issue") {
        info!("Access token validation successful");
        Ok(())
    } else {
        error!("Token does not have required scope");
        Err(IssuerError::InvalidScope)
    }
}

// リクエストの検証関数
pub fn validate_request(req: &CredentialRequest) -> Result<(), IssuerError> {
    info!("Validating request");
    if req.formats.is_empty() {
        return Err(IssuerError::NoCredentialFormats);
    }
    for format in &req.formats {
        if !["jwt_vc_json", "ldp_vc", "sd_jwt_vc"].contains(&format.as_str()) {
            return Err(IssuerError::UnsupportedCredentialFormat(format.clone()));
        }
    }
    if !req.types.contains(&"VerifiableCredential".to_string()) {
        return Err(IssuerError::MissingVerifiableCredentialType);
    }
    if req.proof.proof_type != "jwt" {
        return Err(IssuerError::UnsupportedProofType(
            req.proof.proof_type.clone(),
        ));
    }
    info!("Request validation successful");
    Ok(())
}

// 所有証明の検証関数
pub fn verify_proof_of_possession(
    proof: &Proof,
    client_public_key: &str,
) -> Result<(), IssuerError> {
    info!("Verifying proof of possession");
    let decoding_key = DecodingKey::from_ed_pem(client_public_key.as_ref())
        .map_err(|_| IssuerError::InvalidPublicKeyFormat)?;

    let claims = verify_jwt_with_key(&proof.jwt, &decoding_key)?;
    debug!("Proof JWT successfully verified: {:?}", claims);

    let nonce = claims
        .get("nonce")
        .and_then(|n| n.as_str())
        .ok_or(IssuerError::InvalidNonceInProof)?;

    if verify_nonce(nonce) {
        info!("Proof of possession verification successful");
        Ok(())
    } else {
        Err(IssuerError::NonceVerificationFailed)
    }
}

// タイムスタンプ生成の共通関数
fn generate_timestamps() -> (i64, i64) {
    let now = Utc::now();
    (now.timestamp(), (now + Duration::hours(24)).timestamp())
}

// 共通クレームの初期化関数
fn init_common_claims(issuer: &str) -> Value {
    let (iat, exp) = generate_timestamps();
    serde_json::json!({
        "iss": issuer,
        "sub": Uuid::new_v4().to_string(),
        "iat": iat,
        "exp": exp,
    })
}

// クレデンシャル生成関数
pub fn generate_credential(req: &CredentialRequest) -> Result<String, IssuerError> {
    info!("Generating credential");
    let mut credential = init_common_claims(config::CREDENTIAL_ISSUER);
    credential["vc"] = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "type": req.types.clone(),
        "credentialSubject": USER_DATA.clone()
    });

    let encoding_key = get_encoding_key("CREDENTIAL_ISSUE")?;
    let jwt = generate_jwt(&credential, &encoding_key, None)?;
    info!("Credential generated successfully");
    Ok(jwt)
}

// ノンス関連の関数
pub fn generate_nonce() -> (String, u64) {
    info!("Generating nonce");
    let nonce = generate_salt();
    store_nonce(&nonce, config::NONCE_EXPIRATION);
    info!("Nonce generated successfully");
    (nonce, config::NONCE_EXPIRATION)
}

fn verify_nonce(_nonce: &str) -> bool {
    // 実際の実装ではストレージからノンスを取得し、有効期限を確認
    true
}

fn store_nonce(nonce: &str, _expires_in: u64) {
    debug!("Storing nonce: {}", nonce);
    // 実際の実装ではデータベースなどにノンスを保存
}

// SD-JWT-VC生成関数
pub fn generate_sd_jwt_vc(
    req: &CredentialRequest,
) -> Result<SDJWTVerifiableCredential, IssuerError> {
    info!("Generating SD-JWT VC");

    // 共通クレームを初期化
    let mut claims = init_common_claims(config::CREDENTIAL_ISSUER);

    // SD-JWT-VC固有のvctフィールドを追加
    if let Some(vct) = USER_DATA.get("vct") {
        claims["vct"] = vct.clone();
    }
    claims["_sd_alg"] = serde_json::json!("sha-256");

    // 公開鍵（JWK）情報がある場合は`cnf`フィールドに追加し、Key Binding JWTを生成
    let key_binding_jwt = if let Some(jwk) = &req.cnf {
        claims["cnf"] = jwk.clone(); // `cnf`フィールドに公開鍵を追加
        Some(
            generate_key_binding_jwt(jwk.clone())
                .map_err(|e| IssuerError::SdJwtVcGenerationError(e.to_string()))?,
        )
    } else {
        None
    };

    debug!("{:?}", claims);

    // USER_DATAから選択的開示のクレームを取得し、ハッシュ化とディスクロージャを生成
    let selective_claims: Vec<(&str, serde_json::Value)> = USER_DATA
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k != "vct") // vctは除外
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();

    let (_sd_jwt, disclosures, sd_hashes) = generate_sd_jwt(&claims, &selective_claims)
        .map_err(|e| IssuerError::SdJwtVcGenerationError(e.to_string()))?;
    claims["_sd"] = serde_json::Value::Array(sd_hashes);

    // SD-JWTの署名とエンコード
    let sd_jwt =
        sign_sd_jwt(&claims).map_err(|e| IssuerError::SdJwtVcGenerationError(e.to_string()))?;

    // SD-JWT-VCの検証
    verify_sd_jwt(&sd_jwt)?;

    Ok(SDJWTVerifiableCredential {
        sd_jwt,
        disclosures,
        key_binding_jwt,
    })
}

// SD-JWTの署名関数
fn sign_sd_jwt(claims: &Value) -> Result<String, IssuerError> {
    let header = Header {
        typ: Some("vc+sd-jwt".to_string()),
        alg: Algorithm::EdDSA,
        ..Default::default()
    };
    let encoding_key = get_encoding_key("CREDENTIAL_ISSUE")?;
    generate_jwt(claims, &encoding_key, Some(header))
}

// 選択的開示とハッシュ化関数
fn generate_sd_jwt(
    claims: &Value,
    selective_claims: &[(&str, Value)],
) -> Result<(String, Vec<String>, Vec<Value>), IssuerError> {
    let mut jwt_claims = claims.clone();
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (key, value) in selective_claims {
        let salt = generate_salt();
        let disclosure = format!("[\"{}\", \"{}\", {}]", salt, key, value);
        let encoded_disclosure = general_purpose::URL_SAFE_NO_PAD.encode(&disclosure);
        let hash = hash_disclosure(&disclosure);
        jwt_claims["vc"]["credentialSubject"][*key] = Value::String(hash.clone());
        disclosures.push(encoded_disclosure);
        sd_hashes.push(Value::String(hash));
    }

    Ok((jwt_claims.to_string(), disclosures, sd_hashes))
}

fn generate_key_binding_jwt(jwk: Value) -> Result<String, IssuerError> {
    let claims = serde_json::json!({
        "iat": Utc::now().timestamp(),
        "nonce": generate_salt(),
        "cnf": jwk
    });
    let encoding_key = get_encoding_key("CREDENTIAL_ISSUE")?;
    generate_jwt(&claims, &encoding_key, None)
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

pub fn verify_sd_jwt(sd_jwt: &str) -> Result<Value, IssuerError> {
    info!("Verify SD-JWT");
    let parts: Vec<&str> = sd_jwt.split('.').collect();
    if parts.len() < 2 {
        return Err(IssuerError::InvalidSdJwtFormat);
    }

    let jwt = parts[0..3].join(".");
    let disclosures = &parts[3..];

    let decoding_key = get_decoding_key("CREDENTIAL_ISSUE")?;
    let mut claims = verify_jwt_with_key(&jwt, &decoding_key)?;

    for disclosure in disclosures {
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(disclosure)
            .map_err(|_| IssuerError::InvalidDisclosureEncoding)?;

        let disclosure_json: Value =
            serde_json::from_slice(&decoded).map_err(|_| IssuerError::InvalidDisclosureFormat)?;

        if let (Some(salt), Some(key), Some(value)) = (
            disclosure_json.get(0),
            disclosure_json.get(1),
            disclosure_json.get(2),
        ) {
            let disclosure_str = format!("[\"{}\", \"{}\", {}]", salt, key, value);
            let hash = hash_disclosure(&disclosure_str);
            if claims[key.as_str().unwrap()] == Value::String(hash.clone()) {
                claims[key.as_str().unwrap()] = value.clone();
            }
        }
    }
    info!("Verified SD-JWT-VC!");
    Ok(claims)
}

// トークンエンドポイント関連の関数
pub fn authenticate_client(client_id: &str, client_secret: &str) -> Result<(), IssuerError> {
    if let Some(expected_secret) = get_client_secret_by_id(client_id) {
        if client_secret == expected_secret {
            Ok(())
        } else {
            error!(
                "Client authentication failed: invalid client_secret for client_id {}",
                client_id
            );
            Err(IssuerError::ClientAuthenticationFailed(
                "Invalid client_secret".to_string(),
            ))
        }
    } else {
        error!(
            "Client authentication failed: client_id {} not found",
            client_id
        );
        Err(IssuerError::ClientAuthenticationFailed(
            "Client_id not found".to_string(),
        ))
    }
}

pub fn validate_grant_type(grant_type: &str) -> Result<(), IssuerError> {
    if grant_type != "client_credentials" {
        error!("Unsupported grant type: {}", grant_type);
        Err(IssuerError::UnsupportedGrantType)
    } else {
        Ok(())
    }
}

pub fn generate_access_token(
    client_id: &str,
    scope: Option<&str>,
) -> Result<TokenResponse, IssuerError> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let scope = scope.unwrap_or("credential_issue").to_string();

    if scope != "credential_issue" {
        return Err(IssuerError::InvalidScopeValue);
    }

    let claims = serde_json::json!({
        "iss": "https://example.com",
        "sub": client_id,
        "aud": "https://api.example.com",
        "exp": (now + expires_in).timestamp(),
        "iat": now.timestamp(),
        "scope": scope,
    });

    let encoding_key = get_encoding_key("ACCESS_TOKEN")?;
    let access_token = generate_jwt(&claims, &encoding_key, None)
        .map_err(|e| IssuerError::AccessTokenGenerationError(e.to_string()))?;
    debug!("Generated Access Token: {}", access_token);

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: expires_in.num_seconds() as u64,
        scope,
        c_nonce: Uuid::new_v4().to_string(),
        c_nonce_expires_in: 300,
    })
}
