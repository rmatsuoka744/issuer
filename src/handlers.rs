use crate::db::get_public_key_as_str;
use crate::errors::IssuerError;
use crate::models::{
    CombinedCredentialResponse, CredentialRequest, CredentialResponse, ErrorResponse,
    IssuerMetadata, TokenRequest,
};
use crate::services::{
    authenticate_client, generate_access_token, generate_credential, generate_nonce,
    generate_sd_jwt_vc, validate_access_token, validate_grant_type, validate_request,
    verify_proof_of_possession,
};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use log::{debug, error, info};

#[post("/credential")]
pub async fn credential_endpoint(
    req: HttpRequest,
    body: web::Json<CredentialRequest>,
) -> impl Responder {
    info!("Credential endpoint called");
    debug!("Received credential request: {:?}", body);

    let token = match extract_token(&req) {
        Ok(t) => t,
        Err(response) => return response,
    };

    // アクセストークンの検証
    if let Err(e) = validate_access_token(&token) {
        error!("Access token validation failed: {}", e);
        return map_issuer_error_to_response(e);
    }

    // リクエストの検証
    if let Err(e) = validate_request(&body) {
        error!("Request validation failed: {}", e);
        return map_issuer_error_to_response(e);
    }

    // クライアントの公開鍵を取得
    let client_public_key = match get_public_key_as_str("CLIENT_AUTH") {
        Ok(key) => key,
        Err(_) => {
            error!("Failed to retrieve client public key");
            return HttpResponse::InternalServerError().json(ErrorResponse::new(
                "server_error",
                "Failed to retrieve client public key",
            ));
        }
    };

    // 所有証明の検証
    if let Err(e) = verify_proof_of_possession(&body.proof, &client_public_key) {
        error!("Proof of possession verification failed: {}", e);
        return map_issuer_error_to_response(e);
    }

    let mut response = CombinedCredentialResponse {
        w3c_vc: None,
        sd_jwt_vc: None,
    };

    for format in &body.formats {
        match format.as_str() {
            "jwt_vc_json" => match generate_credential(&body) {
                Ok(credential) => {
                    let (c_nonce, c_nonce_expires_in) = generate_nonce();
                    response.w3c_vc = Some(CredentialResponse {
                        format: "jwt_vc_json".to_string(),
                        credential,
                        c_nonce,
                        c_nonce_expires_in,
                    });
                }
                Err(e) => {
                    error!("Failed to generate credential: {}", e);
                    return map_issuer_error_to_response(e);
                }
            },
            "sd_jwt_vc" => match generate_sd_jwt_vc(&body) {
                Ok(sd_jwt_vc) => {
                    response.sd_jwt_vc = Some(sd_jwt_vc);
                }
                Err(e) => {
                    error!("Failed to generate SD-JWT-VC: {}", e);
                    return map_issuer_error_to_response(e);
                }
            },
            _ => {
                return HttpResponse::BadRequest().json(ErrorResponse::new(
                    "unsupported_format",
                    &format!("Unsupported format: {}", format),
                ));
            }
        }
    }

    info!("Credential endpoint: Successfully processed request");
    HttpResponse::Ok().json(response)
}

#[get("/.well-known/openid-credential-issuer")]
pub async fn metadata_endpoint() -> impl Responder {
    info!("Metadata endpoint called");
    let metadata = IssuerMetadata::default();
    info!("Metadata endpoint: Successfully processed request");
    HttpResponse::Ok().json(metadata)
}

fn extract_token(req: &HttpRequest) -> Result<String, HttpResponse> {
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

#[post("/token")]
async fn token_endpoint(_req: HttpRequest, body: web::Json<TokenRequest>) -> impl Responder {
    info!("Token endpoint called");

    // クライアント認証
    if let Err(e) = authenticate_client(&body.client_id, &body.client_secret) {
        error!(
            "Authentication failed for client_id: {}: {}",
            body.client_id, e
        );
        return map_issuer_error_to_response(e);
    }

    // グラントタイプの検証
    if let Err(e) = validate_grant_type(&body.grant_type) {
        error!("Invalid grant type: {}", e);
        return map_issuer_error_to_response(e);
    }

    // アクセストークンの生成
    match generate_access_token(&body.client_id, body.scope.as_deref()) {
        Ok(token_response) => HttpResponse::Ok().json(token_response),
        Err(e) => {
            error!("Failed to generate access token: {}", e);
            return map_issuer_error_to_response(e);
        }
    }
}

// IssuerErrorをHTTPレスポンスにマッピングするヘルパー関数
fn map_issuer_error_to_response(error: IssuerError) -> HttpResponse {
    match error {
        IssuerError::InvalidScope => HttpResponse::Forbidden().json(ErrorResponse::new(
            "insufficient_scope",
            "Token does not have required scope",
        )),
        IssuerError::MissingScopeClaim => HttpResponse::Unauthorized().json(ErrorResponse::new(
            "invalid_token",
            "Scope claim is missing",
        )),
        IssuerError::JwtDecodingError(_) => HttpResponse::Unauthorized().json(ErrorResponse::new(
            "invalid_token",
            "Invalid or expired token",
        )),
        IssuerError::InvalidNonceInProof => HttpResponse::BadRequest().json(ErrorResponse::new(
            "invalid_proof",
            "Invalid or missing nonce in proof",
        )),
        IssuerError::NonceVerificationFailed => HttpResponse::BadRequest().json(
            ErrorResponse::new("invalid_proof", "Nonce verification failed"),
        ),
        IssuerError::UnsupportedCredentialFormat(format) => {
            HttpResponse::BadRequest().json(ErrorResponse::new(
                "unsupported_format",
                &format!("Unsupported credential format: {}", format),
            ))
        }
        IssuerError::NoCredentialFormats => HttpResponse::BadRequest().json(ErrorResponse::new(
            "invalid_request",
            "No credential formats specified",
        )),
        IssuerError::MissingVerifiableCredentialType => HttpResponse::BadRequest().json(
            ErrorResponse::new("invalid_request", "VerifiableCredential type is missing"),
        ),
        IssuerError::UnsupportedProofType(proof_type) => {
            HttpResponse::BadRequest().json(ErrorResponse::new(
                "invalid_request",
                &format!("Unsupported proof type: {}", proof_type),
            ))
        }
        IssuerError::ClientAuthenticationFailed(_) => HttpResponse::Unauthorized().json(
            ErrorResponse::new("invalid_client", "Client authentication failed"),
        ),
        IssuerError::UnsupportedGrantType => HttpResponse::BadRequest().json(ErrorResponse::new(
            "unsupported_grant_type",
            "Unsupported grant type",
        )),
        IssuerError::InvalidScopeValue => {
            HttpResponse::BadRequest().json(ErrorResponse::new("invalid_scope", "Invalid scope"))
        }
        IssuerError::PrivateKeyLoadError(_) | IssuerError::PublicKeyLoadError(_) => {
            HttpResponse::InternalServerError()
                .json(ErrorResponse::new("server_error", "Key loading error"))
        }
        IssuerError::InvalidPrivateKeyFormat | IssuerError::InvalidPublicKeyFormat => {
            HttpResponse::InternalServerError()
                .json(ErrorResponse::new("server_error", "Invalid key format"))
        }
        IssuerError::JwtEncodingError(_) => HttpResponse::InternalServerError()
            .json(ErrorResponse::new("server_error", "JWT encoding error")),
        IssuerError::SdJwtVcGenerationError(_) => HttpResponse::InternalServerError().json(
            ErrorResponse::new("server_error", "Failed to generate SD-JWT-VC"),
        ),
        IssuerError::InvalidSdJwtFormat
        | IssuerError::InvalidDisclosureEncoding
        | IssuerError::InvalidDisclosureFormat => HttpResponse::BadRequest().json(
            ErrorResponse::new("invalid_request", "Invalid SD-JWT format or disclosure"),
        ),
        IssuerError::AccessTokenGenerationError(_) => HttpResponse::InternalServerError().json(
            ErrorResponse::new("server_error", "Failed to generate access token"),
        ),
    }
}
