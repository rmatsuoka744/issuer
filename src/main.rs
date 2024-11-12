mod config;
mod db;
mod handlers;
mod models;
mod services;
mod user_data;
mod utils;

use actix_web::{App, HttpServer};
use log::info;
use utils::Jwk;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));
    info!("Starting server");

    let test_token = services::generate_test_access_token();
    let test_proof_jwt = services::generate_test_proof_jwt();
    let test_jwk = serde_json::to_value(&Jwk::test()).unwrap();
    info!("Test Access Token: {}", test_token);
    info!("Test Proof JWT: {}", test_proof_jwt);
    info!("Test Holder JWK: {}", test_jwk);
    info!(
        "Metadata Endpoint: curl -X GET http://localhost:8080/.well-known/openid-credential-issuer"
    );
    info!(
        r#"Test curl command:
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/json" \
  -d '{{
    "grant_type": "client_credentials",
    "client_id": "TEST_CLIENT_ID_1",
    "client_secret": "TEST_SECRET_1",
    "scope": "credential_issue"
    }}'"#
    );
    info!(
        r#"Test curl command:
curl -X POST http://localhost:8080/credential \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {}" \
  -d '{{
    "formats": ["jwt_vc_json", "sd_jwt_vc"],
    "types": ["VerifiableCredential", "UniversityDegreeCredential"],
    "cnf": {{
      "jwk": {}
    }},
    "proof": {{
      "proof_type": "jwt",
      "jwt": "{}"
    }}
  }}'"#,
        test_token, test_jwk, test_proof_jwt
    );

    HttpServer::new(|| {
        App::new()
            .service(handlers::credential_endpoint)
            .service(handlers::metadata_endpoint)
            .service(handlers::token_endpoint)
    })
    .bind(config::SERVER_ADDRESS)?
    .run()
    .await
}
