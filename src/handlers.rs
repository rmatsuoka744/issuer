use crate::errors::map_issuer_error_to_response;
use crate::models::{CredentialRequest, IssuerMetadata, TokenRequest};
use crate::services::{
    exp_generate_sd_jwt_vc, extract_token, process_credential_request, process_token_request, validate_access_token, validate_request, verify_proof_of_possession
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

    // Exp:
    let exp_sd_jwt = exp_generate_sd_jwt_vc(&body).unwrap();
    debug!("Experimental: {}", exp_sd_jwt);

    // アクセストークンの抽出
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

    // 所有証明の検証
    if let Err(e) = verify_proof_of_possession(&body) {
        error!("Proof of possession verification failed: {}", e);
        return map_issuer_error_to_response(e);
    }

    // クレデンシャルの生成（関数化した処理を呼び出す）
    let response = match process_credential_request(&body) {
        Ok(res) => res,
        Err(e) => {
            error!("Failed to process credential request: {}", e);
            return map_issuer_error_to_response(e);
        }
    };

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

#[post("/token")]
async fn token_endpoint(_req: HttpRequest, body: web::Json<TokenRequest>) -> impl Responder {
    info!("Token endpoint called");

    match process_token_request(&body) {
        Ok(token_response) => HttpResponse::Ok().json(token_response),
        Err(e) => {
            error!("Failed to process token request: {}", e);
            return map_issuer_error_to_response(e);
        }
    }
}
