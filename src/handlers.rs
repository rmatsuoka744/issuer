use crate::models::{
    CombinedCredentialResponse, CredentialRequest, CredentialResponse, ErrorResponse,
    IssuerMetadata, TokenRequest,
};
use crate::services::{
    generate_credential, generate_nonce, generate_sd_jwt_vc, validate_access_token,
    validate_request, verify_proof_of_possession, authenticate_client, validate_grant_type, generate_access_token
};
use crate::config;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use log::{debug, info, error};

// handlers.rs

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

    if !verify_proof_of_possession(&body.proof, &config::CLIENT_SECRET) {
        return HttpResponse::BadRequest().json(ErrorResponse::new(
            "invalid_proof",
            "The proof of possession is invalid",
        ));
    }

    let mut response = CombinedCredentialResponse {
        w3c_vc: None,
        sd_jwt_vc: None,
    };

    for format in &body.formats {
        match format.as_str() {
            "jwt_vc_json" => {
                let credential = generate_credential(&body);
                let (c_nonce, c_nonce_expires_in) = generate_nonce();
                response.w3c_vc = Some(CredentialResponse {
                    format: "jwt_vc_json".to_string(),
                    credential,
                    c_nonce,
                    c_nonce_expires_in,
                });
            }
            "sd_jwt_vc" => {
                match generate_sd_jwt_vc(&body) {
                    Ok(sd_jwt_vc) => {
                        response.sd_jwt_vc = Some(sd_jwt_vc);
                    },
                    Err(err) => {
                        error!("Failed to generate SD-JWT-VC: {}", err);
                        return HttpResponse::InternalServerError().json(ErrorResponse::new(
                            "server_error",
                            "Failed to generate SD-JWT-VC",
                        ));
                    }
                }
            }
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
    debug!("Received token request: {:?}", body);

    if !authenticate_client(&body.client_id, &body.client_secret) {
        return HttpResponse::Unauthorized().json(ErrorResponse::new(
            "invalid_client",
            "Client authentication failed",
        ));
    }

    if !validate_grant_type(&body.grant_type) {
        return HttpResponse::BadRequest().json(ErrorResponse::new(
            "unsupported_grant_type",
            "Unsupported grant type",
        ));
    }

    match generate_access_token(&body.client_id, body.scope.as_deref()) {
        Ok(token_response) => HttpResponse::Ok().json(token_response),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse::new(
            "server_error",
            &e.to_string(),
        )),
    }
}