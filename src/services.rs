use crate::config;
use crate::db::{get_client_secret_by_id, get_private_key_as_str, get_public_key_as_str};
use crate::errors::IssuerError;
use crate::models::{
    CredentialRequest, CredentialResponse, ErrorResponse, SDJWTVerifiableCredential, TokenRequest,
    TokenResponse, W3CVerifiableCredential,
};
use crate::user_data::{MY_NUMBER, USER_DATA};
use crate::utils;
use actix_web::{HttpRequest, HttpResponse};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, decode_header, encode, jwk, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use log::{debug, error, info};
use sdjwt::{Algorithm as SDJWTAlgorithm, Header as SDJWTHeader, Issuer, Jwk, KeyForEncoding};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use uuid::Uuid;

// キー取得のヘルパー関数
fn get_encoding_key(key_type: &str) -> Result<EncodingKey, IssuerError> {
    let private_key = get_private_key_as_str(key_type)
        .map_err(|_| IssuerError::PrivateKeyLoadError(key_type.to_string()))?;
    EncodingKey::from_ec_pem(private_key.as_ref())
        .map_err(|e| IssuerError::InvalidPrivateKeyFormat(e.to_string()))
}

fn get_decoding_key(key_type: &str) -> Result<DecodingKey, IssuerError> {
    let public_key = get_public_key_as_str(key_type)
        .map_err(|_| IssuerError::PublicKeyLoadError(key_type.to_string()))?;
    DecodingKey::from_ec_pem(public_key.as_ref())
        .map_err(|e| IssuerError::InvalidPublicKeyFormat(e.to_string()))
}

// テスト用のJWT生成関数
pub fn generate_test_access_token() -> Result<String, IssuerError> {
    info!("Generate test access token");
    let expiration = Utc::now() + Duration::minutes(20);

    let claims =
        create_access_token_claims("test_user", "credential_issue", expiration.timestamp())?;
    let encoding_key = get_encoding_key("ACCESS_TOKEN_p256")?;
    generate_jwt(&claims, &encoding_key, None)
}

pub fn generate_test_proof_jwt(jwk: &jwk::Jwk) -> Result<String, IssuerError> {
    info!("Generate test proof jwt");
    let expiration = Utc::now() + Duration::minutes(20);
    let claims = serde_json::json!({
        "nonce": "test_nonce",
        "iat": Utc::now().timestamp(),
        "exp": expiration.timestamp()
    });
    let encoding_key = get_encoding_key("CLIENT_AUTH_p256")?;
    let mut header = Header::new(Algorithm::from_str(config::CREDENTIAL_KEYTYPE).unwrap());
    header.typ = Some("openid4vci-proof+jwt".to_string());
    header.jwk = Some(jwk.clone());
    generate_jwt(&claims, &encoding_key, Some(header))
}

// JWT生成の共通関数
fn generate_jwt(
    claims: &Value,
    encoding_key: &EncodingKey,
    header: Option<Header>,
) -> Result<String, IssuerError> {
    let header = header
        .unwrap_or_else(|| Header::new(Algorithm::from_str(config::CREDENTIAL_KEYTYPE).unwrap()));
    encode(&header, claims, encoding_key).map_err(|e| IssuerError::JwtEncodingError(e.to_string()))
}

// JWT検証の共通関数
fn verify_jwt_with_key(token: &str, decoding_key: &DecodingKey) -> Result<Value, IssuerError> {
    let validation = Validation::new(Algorithm::from_str(config::CREDENTIAL_KEYTYPE).unwrap());
    let token_data = decode::<Value>(token, decoding_key, &validation)
        .map_err(|e| IssuerError::JwtDecodingError(e.to_string()))?;
    Ok(token_data.claims)
}

// アクセストークンの検証関数
pub fn validate_access_token(token: &str) -> Result<(), IssuerError> {
    info!("Validating access token");
    let decoding_key = get_decoding_key("ACCESS_TOKEN_p256")?;
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
pub fn verify_proof_of_possession(body: &CredentialRequest) -> Result<(), IssuerError> {
    // JWK からデコーディングキーを取得
    let decoding_key =
        utils::get_decoding_key_from_jwk(body).map_err(|_| IssuerError::InvalidProofKey)?;

    // JWT の検証
    let validation = Validation::new(Algorithm::from_str(config::CREDENTIAL_KEYTYPE).unwrap());

    let token_data = decode::<Value>(&body.proof.jwt, &decoding_key, &validation)
        .map_err(|e| IssuerError::JwtDecodingError(e.to_string()))?;

    debug!("Proof JWT successfully verified: {:?}", token_data.claims);

    // nonce の抽出と検証
    let nonce = token_data
        .claims
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

// ノンス関連の関数
pub fn generate_nonce() -> (String, u64) {
    info!("Generating nonce");
    let nonce = generate_salt();
    store_nonce(&nonce, config::NONCE_EXPIRATION);
    info!("Nonce generated successfully");
    (nonce, config::NONCE_EXPIRATION)
}

fn verify_nonce(_nonce: &str) -> bool {
    // TODO: Implement nonce verification with actual storage
    true
}

fn store_nonce(nonce: &str, _expires_in: u64) {
    debug!("Storing nonce: {}", nonce);
    // TODO: Implement nonce storage mechanism
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

    let encoding_key = get_encoding_key("CREDENTIAL_ISSUE_p256")?;
    let jwt = generate_jwt(&credential, &encoding_key, None)?;
    info!("Credential generated successfully");
    Ok(jwt)
}

/// 再帰的にパスを探索し、全てのパスを Vec<String> として返す
fn flatten_json_keys(value: &Value, prefix: &str) -> Vec<String> {
    let mut paths = Vec::new();

    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let full_key = if prefix.is_empty() {
                    format!("/{}", key)
                } else {
                    format!("{}/{}", prefix, key)
                };
                paths.extend(flatten_json_keys(val, &full_key));
            }
        }
        Value::Array(array) => {
            for (index, val) in array.iter().enumerate() {
                let full_key = format!("{}/{}", prefix, index);
                paths.extend(flatten_json_keys(val, &full_key));
            }
        }
        _ => {
            // スカラー値の場合は現在のパスを追加
            paths.push(prefix.to_string());
        }
    }

    paths
}

/// 階層構造を持つフィールドから選択的開示用のパスを生成する
fn get_selective_claims_paths(value: &Value) -> Vec<String> {
    flatten_json_keys(value, "")
}

pub fn exp_generate_sd_jwt_vc(req: &CredentialRequest) -> Result<String, IssuerError> {
    info!("Exp: Generating SD-JWT VC");

    let mut header = SDJWTHeader::new(SDJWTAlgorithm::ES256);
    header.typ = Some("application/example+sd-jwt".to_string());

    let holder_jwk = Jwk::from_value(
        extract_holder_public_key(req)
            .unwrap()
            .unwrap()
            .get("jwk")
            .unwrap()
            .clone(),
    )
    .unwrap();
    debug!("{:?}", holder_jwk);

    let mut holder_claims = serde_json::json!({
        "iss": config::CREDENTIAL_ISSUER,
        "iat": Utc::now().timestamp(),
        "vct": "https://credentials.example.com/identity_credential"
    });
    holder_claims
        .as_object_mut()
        .unwrap()
        .extend(MY_NUMBER.as_object().unwrap().clone());

    let selective_clamis: Vec<String> = get_selective_claims_paths(&MY_NUMBER);
    
    let credential_key_str = get_private_key_as_str("CREDENTIAL_ISSUE_p256").unwrap();
    let credential_key_bytes = credential_key_str.as_bytes();
    let encoding_key = KeyForEncoding::from_ec_pem(credential_key_bytes).unwrap();

    let sdjwt = Issuer::new(holder_claims)
        .unwrap()
        .header(header)
        .expires_in_seconds(1000)
        .iter_disclosable(selective_clamis.iter())
        .require_key_binding(holder_jwk)
        .encode(&encoding_key)
        .unwrap();

    Ok(sdjwt)
}

// SD-JWT-VC生成関数
pub fn generate_sd_jwt_vc(
    req: &CredentialRequest,
) -> Result<SDJWTVerifiableCredential, IssuerError> {
    info!("Generating SD-JWT VC");

    // 共通クレームを初期化
    let mut claims = initialize_sd_jwt_vc_claims().map_err(|e| {
        IssuerError::SdJwtVcGenerationError(format!("Failed to initialize claims: {}", e))
    })?;

    // 選択的開示のクレームを取得
    let selective_claims = get_selective_claims(&USER_DATA).map_err(|e| {
        IssuerError::SdJwtVcGenerationError(format!("Failed to get selective claims: {}", e))
    })?;

    // 選択的開示の処理
    let (disclosures, _) =
        process_selective_disclosures(&mut claims, &selective_claims).map_err(|e| {
            IssuerError::SdJwtVcGenerationError(format!(
                "Failed to process selective disclosures: {}",
                e
            ))
        })?;

    // Holder公開鍵がリクエストに含まれているかチェック
    if let Some(jwk_value) = extract_holder_public_key(req).map_err(|e| {
        IssuerError::SdJwtVcGenerationError(format!("Failed to extract holder public key: {}", e))
    })? {
        claims["cnf"] = jwk_value;
    }

    // SD-JWTの署名とエンコード
    let sd_jwt = sign_sd_jwt(&claims).map_err(|e| {
        IssuerError::SdJwtVcGenerationError(format!("Failed to sign SD-JWT: {}", e))
    })?;

    // SD-JWT-VCの検証
    verify_sd_jwt(&sd_jwt).map_err(|e| {
        IssuerError::SdJwtVcGenerationError(format!("Failed to verify SD-JWT: {}", e))
    })?;

    Ok(SDJWTVerifiableCredential {
        sd_jwt,
        disclosures,
    })
}

pub fn _create_sdjwt_response(vc: &SDJWTVerifiableCredential) -> String {
    let mut comp = vec![vc.sd_jwt.clone()];
    // disclosuresを追加
    comp.extend(vc.disclosures.clone());
    // ~で連結
    comp.join("~")
}

// SD-JWTの署名関数
fn sign_sd_jwt(claims: &Value) -> Result<String, IssuerError> {
    let header = Header {
        typ: Some("vc+sd-jwt".to_string()),
        alg: Algorithm::from_str(config::CREDENTIAL_KEYTYPE).unwrap(),
        ..Default::default()
    };
    let encoding_key = get_encoding_key("CREDENTIAL_ISSUE_p256")?;
    generate_jwt(claims, &encoding_key, Some(header))
}

// 選択的開示とハッシュ化関数
fn process_selective_disclosures(
    claims: &mut Value,
    selective_claims: &[(&str, Value)],
) -> Result<(Vec<String>, Vec<Value>), IssuerError> {
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (key, value) in selective_claims {
        let salt = generate_salt();
        let disclosure_value = serde_json::json!([salt, key, value]);
        let disclosure_str = serde_json::to_string(&disclosure_value)
            .map_err(|e| IssuerError::InvalidDisclosureFormat(e.to_string()))?;
        let encoded_disclosure = general_purpose::URL_SAFE_NO_PAD.encode(&disclosure_str);
        let hash = hash_disclosure(&encoded_disclosure);
        disclosures.push(encoded_disclosure);
        sd_hashes.push(Value::String(hash));
    }

    claims["_sd"] = serde_json::Value::Array(sd_hashes.clone());
    Ok((disclosures, sd_hashes))
}

fn generate_salt() -> String {
    Uuid::new_v4().to_string()
}

fn hash_disclosure(encoded_disclosure: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encoded_disclosure.as_bytes());
    let result = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

pub fn verify_sd_jwt(sd_jwt: &str) -> Result<Value, IssuerError> {
    info!("Verify SD-JWT");
    let parts: Vec<&str> = sd_jwt.split('~').collect();
    if parts.is_empty() {
        return Err(IssuerError::InvalidSdJwtFormat);
    }

    let jwt = parts[0];
    let disclosures = &parts[1..];

    let decoding_key = get_decoding_key("CREDENTIAL_ISSUE_p256")?;
    let mut claims = verify_jwt_with_key(jwt, &decoding_key)?;

    // ディスクロージャの処理
    process_disclosures(&mut claims, disclosures)?;

    info!("Verified SD-JWT-VC!");
    Ok(claims)
}

// ディスクロージャの処理関数
fn process_disclosures(claims: &mut Value, disclosures: &[&str]) -> Result<(), IssuerError> {
    for disclosure in disclosures {
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(disclosure)
            .map_err(|e| IssuerError::InvalidDisclosureEncoding(e.to_string()))?;

        let disclosure_value: Value = serde_json::from_slice(&decoded)
            .map_err(|e| IssuerError::InvalidDisclosureFormat(e.to_string()))?;

        if let Some(array) = disclosure_value.as_array() {
            if array.len() != 3 {
                return Err(IssuerError::InvalidDisclosureFormat(
                    "Invalid array length".to_string(),
                ));
            }
            let key = array[1].as_str().ok_or_else(|| {
                IssuerError::InvalidDisclosureKeyFormat("Key is not a string".to_string())
            })?;
            let value = &array[2];

            let disclosure_str = serde_json::to_string(&disclosure_value)
                .map_err(|e| IssuerError::InvalidDisclosureFormat(e.to_string()))?;
            let encoded_disclosure = general_purpose::URL_SAFE_NO_PAD.encode(&disclosure_str);
            let hash = hash_disclosure(&encoded_disclosure);

            if claims[key] == Value::String(hash.clone()) {
                claims[key] = value.clone();
            } else {
                return Err(IssuerError::DisclosureHashMismatch);
            }
        } else {
            return Err(IssuerError::InvalidDisclosureFormat(
                "Disclosure is not an array".to_string(),
            ));
        }
    }
    Ok(())
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
        Err(IssuerError::UnsupportedGrantType(grant_type.to_string()))
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
        return Err(IssuerError::InvalidScopeValue(scope));
    }

    let claims = create_access_token_claims(client_id, &scope, (now + expires_in).timestamp())?;

    let encoding_key = get_encoding_key("ACCESS_TOKEN_p256")?;
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

// アクセストークンクレームの作成関数
fn create_access_token_claims(
    client_id: &str,
    scope: &str,
    expiration: i64,
) -> Result<Value, IssuerError> {
    Ok(serde_json::json!({
        "iss": config::CREDENTIAL_ISSUER,
        "sub": client_id,
        "aud": config::ACCESS_TOKEN_AUD,
        "exp": expiration,
        "iat": Utc::now().timestamp(),
        "scope": scope,
    }))
}

pub fn process_credential_request(
    req: &CredentialRequest,
) -> Result<CredentialResponse, IssuerError> {
    let mut response = CredentialResponse {
        w3c_vc: None,
        sd_jwt_vc: None,
    };

    for format in &req.formats {
        match format.as_str() {
            "jwt_vc_json" => {
                let credential = generate_credential(req)?;
                let (c_nonce, c_nonce_expires_in) = generate_nonce();
                response.w3c_vc = Some(W3CVerifiableCredential {
                    format: "jwt_vc_json".to_string(),
                    credential,
                    c_nonce,
                    c_nonce_expires_in,
                });
            }
            "sd_jwt_vc" => {
                let sd_jwt_vc = generate_sd_jwt_vc(req)?;
                response.sd_jwt_vc = Some(sd_jwt_vc);
            }
            _ => {
                return Err(IssuerError::UnsupportedCredentialFormat(format.clone()));
            }
        }
    }

    Ok(response)
}

pub fn process_token_request(body: &TokenRequest) -> Result<TokenResponse, IssuerError> {
    // クライアント認証
    authenticate_client(&body.client_id, &body.client_secret)?;

    // グラントタイプの検証
    validate_grant_type(&body.grant_type)?;

    // アクセストークンの生成
    generate_access_token(&body.client_id, body.scope.as_deref())
}

pub fn extract_token(req: &HttpRequest) -> Result<String, HttpResponse> {
    match req.headers().get("Authorization") {
        Some(auth_header) => {
            let auth_str = auth_header.to_str().unwrap_or("");
            if auth_str.starts_with("Bearer ") {
                Ok(auth_str[7..].to_string())
            } else {
                Err(HttpResponse::Unauthorized().json(ErrorResponse::new(
                    "invalid_token",
                    "Invalid Authorization header format",
                )))
            }
        }
        None => Err(HttpResponse::Unauthorized().json(ErrorResponse::new(
            "invalid_token",
            "Missing Authorization header",
        ))),
    }
}

// ユーティリティ関数
fn extract_holder_public_key(req: &CredentialRequest) -> Result<Option<Value>, IssuerError> {
    if let Some(cnf) = &req.cnf {
        debug!("Found jwk in req.cnf: {:?}", cnf);
        Ok(Some(cnf.clone()))
    } else {
        debug!("req.cnf not found, checking proof.jwt...");
        match decode_header(&req.proof.jwt) {
            Ok(header) => {
                if let Some(jwk) = &header.jwk {
                    debug!("Found jwk in proof.jwt header: {:?}", jwk);
                    serde_json::to_value(jwk)
                        .map(Some)
                        .map_err(|e| IssuerError::InvalidJwkFormat(e.to_string()))
                } else {
                    debug!("No jwk found in proof.jwt header.");
                    Ok(None)
                }
            }
            Err(e) => {
                debug!("Failed to decode proof.jwt header: {}", e);
                Err(IssuerError::InvalidProofJwtHeader(e.to_string()))
            }
        }
    }
}

fn get_selective_claims(user_data: &Value) -> Result<Vec<(&str, Value)>, IssuerError> {
    let user_data_map = user_data
        .as_object()
        .ok_or(IssuerError::InvalidUserDataFormat)?;
    Ok(user_data_map
        .iter()
        .filter(|(k, _)| *k != "vct")
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect())
}

fn initialize_sd_jwt_vc_claims() -> Result<Value, IssuerError> {
    let mut claims = init_common_claims(config::CREDENTIAL_ISSUER);
    if let Some(vct) = USER_DATA.get("vct") {
        claims["vct"] = vct.clone();
    }
    claims["_sd_alg"] = Value::String("SHA-256".to_string());
    Ok(claims)
}
