mod config;
mod db;
mod errors;
mod handlers;
mod models;
mod services;
mod user_data;
mod utils;

use actix_web::{App, HttpServer};
use db::get_public_key_as_str;
use log::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));
    info!("Starting server");

    let test_jwk_from_pem =
        utils::from_pem_to_jwk(get_public_key_as_str("CLIENT_AUTH").unwrap().as_str()).unwrap();
    info!("Test Jwk From CLIENT_PUBLIC Pem: {:?}", test_jwk_from_pem);
    let test_jwk_from_pem_p256 = utils::from_pem_to_jwk_p256(get_public_key_as_str("p256").unwrap().as_str()).unwrap();
    info!("Test p256 Jwk From CLIENT_PUBLIC Pem: {:?}", test_jwk_from_pem_p256);
    let test_pem_from_jwk = utils::from_jwk_to_pem(&test_jwk_from_pem).unwrap();
    info!("Test Pem From CLIENT_PUBLIC Jwk: {}", test_pem_from_jwk);
    let test_value_from_jwk = utils::from_jwk_to_value(&test_jwk_from_pem).unwrap();
    info!("Test Jwk Value: {}", test_value_from_jwk);
    let test_value_from_jwk_p256 = utils::from_jwk_to_value_p256(&test_jwk_from_pem_p256).unwrap();
    info!("Test Jwk Value: {}", test_value_from_jwk_p256);
    let test_token = services::generate_test_access_token().unwrap();
    info!("Test Access Token: {}", test_token);
    let test_proof_jwt = services::generate_test_proof_jwt(&test_jwk_from_pem).unwrap();
    info!("Test Proof JWT: {}", test_proof_jwt);
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
        test_token, test_value_from_jwk, test_proof_jwt
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
