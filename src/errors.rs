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
