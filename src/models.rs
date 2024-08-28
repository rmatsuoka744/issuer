use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct CredentialRequest {
    pub format: String,
    pub types: Vec<String>,
    pub proof: Proof,
}

#[derive(Deserialize, Debug)]
pub struct Proof {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Serialize)]
pub struct CredentialResponse {
    pub format: String,
    pub credential: String,
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
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
            credential_issuer: "https://example.com".to_string(),
            credential_endpoint: "https://example.com/credential".to_string(),
            credentials_supported: vec![CredentialMetadata {
                format: "jwt_vc_json".to_string(),
                types: vec![
                    "VerifiableCredential".to_string(),
                    "UniversityDegreeCredential".to_string(),
                ],
            }],
        }
    }
}
