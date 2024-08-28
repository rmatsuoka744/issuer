use crate::models::{CredentialRequest, CredentialResponse, ErrorResponse, IssuerMetadata};
use crate::services::{
    generate_credential, generate_nonce, validate_access_token, validate_request,
    verify_proof_of_possession,
};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use log::{debug, info};

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

    if !validate_access_token(&token) {
        return HttpResponse::Unauthorized().json(ErrorResponse::new(
            "invalid_token",
            "The access token is invalid",
        ));
    }

    if !validate_request(&body) {
        return HttpResponse::BadRequest().json(ErrorResponse::new(
            "invalid_request",
            "The request is missing a required parameter",
        ));
    }

    if !verify_proof_of_possession(&body.proof) {
        return HttpResponse::BadRequest().json(ErrorResponse::new(
            "invalid_proof",
            "The proof of possession is invalid",
        ));
    }

    let credential = generate_credential(&body);
    let (c_nonce, c_nonce_expires_in) = generate_nonce();

    let response = CredentialResponse {
        format: body.format.clone(),
        credential,
        c_nonce,
        c_nonce_expires_in,
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
