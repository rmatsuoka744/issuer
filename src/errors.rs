use crate::models::ErrorResponse;
use actix_web::HttpResponse;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IssuerError {
    #[error("Failed to load private key for {0}")]
    PrivateKeyLoadError(String),

    #[error("Failed to load public key for {0}")]
    PublicKeyLoadError(String),

    #[error("Invalid private key format: {0}")]
    InvalidPrivateKeyFormat(String),

    #[error("Invalid public key format: {0}")]
    InvalidPublicKeyFormat(String),

    #[error("JWT encoding error: {0}")]
    JwtEncodingError(String),

    #[error("JWT decoding error: {0}")]
    JwtDecodingError(String),

    #[error("Scope claim is missing in the token")]
    MissingScopeClaim,

    #[error("Token does not have the required scope")]
    InvalidScope,

    #[error("No credential formats specified in the request")]
    NoCredentialFormats,

    #[error("Unsupported credential format: {0}")]
    UnsupportedCredentialFormat(String),

    #[error("VerifiableCredential type is missing in the request")]
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

    #[error("Invalid disclosure encoding: {0}")]
    InvalidDisclosureEncoding(String),

    #[error("Invalid disclosure format: {0}")]
    InvalidDisclosureFormat(String),

    #[error("Client authentication failed: {0}")]
    ClientAuthenticationFailed(String),

    #[error("Unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    #[error("Invalid scope value: {0}")]
    InvalidScopeValue(String),

    #[error("Failed to generate access token: {0}")]
    AccessTokenGenerationError(String),

    #[error("Invalid proof key")]
    InvalidProofKey,

    #[error("Invalid disclosure key format: {0}")]
    InvalidDisclosureKeyFormat(String),

    #[error("Disclosure hash does not match")]
    DisclosureHashMismatch,

    #[error("Invalid JWK format: {0}")]
    InvalidJwkFormat(String),

    #[error("Invalid proof JWT header: {0}")]
    InvalidProofJwtHeader(String),

    #[error("Invalid user data format")]
    InvalidUserDataFormat,
}

// IssuerErrorをHTTPレスポンスにマッピングする関数
pub fn map_issuer_error_to_response(error: IssuerError) -> HttpResponse {
    match error {
        IssuerError::InvalidScope => HttpResponse::Forbidden().json(ErrorResponse::new(
            "insufficient_scope",
            "Token does not have the required scope",
        )),
        IssuerError::MissingScopeClaim => HttpResponse::Unauthorized().json(ErrorResponse::new(
            "invalid_token",
            "Scope claim is missing in the token",
        )),
        IssuerError::JwtDecodingError(_) => HttpResponse::Unauthorized().json(ErrorResponse::new(
            "invalid_token",
            "Invalid or expired token",
        )),
        IssuerError::InvalidNonceInProof | IssuerError::NonceVerificationFailed => {
            HttpResponse::BadRequest().json(ErrorResponse::new(
                "invalid_proof",
                "Nonce verification failed or nonce is invalid",
            ))
        }
        IssuerError::UnsupportedCredentialFormat(format) => {
            HttpResponse::BadRequest().json(ErrorResponse::new(
                "unsupported_format",
                &format!("Unsupported credential format: {}", format),
            ))
        }
        IssuerError::NoCredentialFormats => HttpResponse::BadRequest().json(ErrorResponse::new(
            "invalid_request",
            "No credential formats specified in the request",
        )),
        IssuerError::MissingVerifiableCredentialType => {
            HttpResponse::BadRequest().json(ErrorResponse::new(
                "invalid_request",
                "VerifiableCredential type is missing in the request",
            ))
        }
        IssuerError::UnsupportedProofType(proof_type) => {
            HttpResponse::BadRequest().json(ErrorResponse::new(
                "invalid_request",
                &format!("Unsupported proof type: {}", proof_type),
            ))
        }
        IssuerError::ClientAuthenticationFailed(_) => HttpResponse::Unauthorized().json(
            ErrorResponse::new("invalid_client", "Client authentication failed"),
        ),
        IssuerError::UnsupportedGrantType(grant_type) => {
            HttpResponse::BadRequest().json(ErrorResponse::new(
                "unsupported_grant_type",
                &format!("Unsupported grant type: {}", grant_type),
            ))
        }
        IssuerError::InvalidScopeValue(scope) => HttpResponse::BadRequest().json(
            ErrorResponse::new("invalid_scope", &format!("Invalid scope: {}", scope)),
        ),
        IssuerError::PrivateKeyLoadError(_)
        | IssuerError::PublicKeyLoadError(_)
        | IssuerError::InvalidPrivateKeyFormat(_)
        | IssuerError::InvalidPublicKeyFormat(_)
        | IssuerError::AccessTokenGenerationError(_)
        | IssuerError::SdJwtVcGenerationError(_)
        | IssuerError::InvalidUserDataFormat => HttpResponse::InternalServerError()
            .json(ErrorResponse::new("server_error", "Internal server error")),
        IssuerError::JwtEncodingError(_) => HttpResponse::InternalServerError()
            .json(ErrorResponse::new("server_error", "JWT encoding error")),
        IssuerError::InvalidSdJwtFormat
        | IssuerError::InvalidDisclosureEncoding(_)
        | IssuerError::InvalidDisclosureFormat(_)
        | IssuerError::InvalidProofKey
        | IssuerError::InvalidDisclosureKeyFormat(_)
        | IssuerError::DisclosureHashMismatch
        | IssuerError::InvalidJwkFormat(_)
        | IssuerError::InvalidProofJwtHeader(_) => HttpResponse::BadRequest().json(
            ErrorResponse::new("invalid_request", "Invalid input data or format"),
        ),
    }
}
