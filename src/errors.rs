use crate::models::ErrorResponse;
use actix_web::HttpResponse;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IssuerError {
    #[error("Failed to load private key for {0}")]
    PrivateKeyLoadError(String),

    #[error("Failed to load public key for {0}")]
    PublicKeyLoadError(String),

    #[error("Invalid EdDSA private key format")]
    InvalidPrivateKeyFormat,

    #[error("Invalid EdDSA public key format")]
    InvalidPublicKeyFormat,

    #[error("JWT encoding error: {0}")]
    JwtEncodingError(String),

    #[error("JWT decoding error: {0}")]
    JwtDecodingError(String),

    #[error("Scope claim is missing")]
    MissingScopeClaim,

    #[error("Token does not have required scope")]
    InvalidScope,

    #[error("No credential formats specified")]
    NoCredentialFormats,

    #[error("Unsupported credential format: {0}")]
    UnsupportedCredentialFormat(String),

    #[error("VerifiableCredential type is missing")]
    MissingVerifiableCredentialType,

    #[error("Unsupported proof type: {0}")]
    UnsupportedProofType(String),

    #[error("Invalid or missing nonce in proof")]
    InvalidNonceInProof,

    #[error("Nonce verification failed")]
    NonceVerificationFailed,

    #[error("Failed to generate SD-JWT-VC: {0}")]
    SdJwtVcGenerationError(String),

    #[error("Invalid SD-JWT format")]
    InvalidSdJwtFormat,

    #[error("Invalid disclosure encoding")]
    InvalidDisclosureEncoding,

    #[error("Invalid disclosure format")]
    InvalidDisclosureFormat,

    #[error("Client authentication failed: {0}")]
    ClientAuthenticationFailed(String),

    #[error("Unsupported grant type")]
    UnsupportedGrantType,

    #[error("Invalid scope")]
    InvalidScopeValue,

    #[error("Failed to generate access token: {0}")]
    AccessTokenGenerationError(String),
}

// IssuerErrorをHTTPレスポンスにマッピングするヘルパー関数
pub fn map_issuer_error_to_response(error: IssuerError) -> HttpResponse {
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
