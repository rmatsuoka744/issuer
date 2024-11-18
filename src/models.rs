use crate::config;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct CredentialRequest {
    pub formats: Vec<String>,
    pub types: Vec<String>,
    pub proof: Proof,
    pub cnf: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
pub struct Proof {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Serialize)]
pub struct W3CVerifiableCredential {
    pub format: String,
    pub credential: String,
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

#[derive(Serialize)]
pub struct SDJWTVerifiableCredential {
    pub sd_jwt: String,
    pub disclosures: Vec<String>,
    pub key_binding_jwt: Option<String>,
}

#[derive(Serialize)]
pub struct CredentialResponse {
    pub w3c_vc: Option<W3CVerifiableCredential>,
    pub sd_jwt_vc: Option<SDJWTVerifiableCredential>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

impl ErrorResponse {
    pub fn new(error: &str, description: &str) -> Self {
        Self {
            error: error.to_string(),
            error_description: description.to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct IssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credentials_supported: Vec<CredentialMetadata>,
}

#[derive(Serialize)]
pub struct CredentialMetadata {
    pub format: String,
    pub types: Vec<String>,
}

impl Default for IssuerMetadata {
    fn default() -> Self {
        Self {
            credential_issuer: config::CREDENTIAL_ISSUER.to_string(),
            credential_endpoint: format!("{}/credential", config::CREDENTIAL_ISSUER),
            credentials_supported: config::SUPPORTED_FORMATS
                .iter()
                .map(|&format| CredentialMetadata {
                    format: format.to_string(),
                    types: vec![
                        "VerifiableCredential".to_string(),
                        "UniversityDegreeCredential".to_string(),
                    ],
                })
                .collect(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}
