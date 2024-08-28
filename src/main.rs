mod config;
mod handlers;
mod models;
mod services;
mod user_data;

use actix_web::{App, HttpServer};
use log::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));
    info!("Starting server");

    let test_token = services::generate_test_access_token();
    let test_proof_jwt = services::generate_test_proof_jwt();
    info!("Test Access Token: {}", test_token);
    info!("Test Proof JWT: {}", test_proof_jwt);
    info!(
        r#"Test curl command:
curl -X POST http://localhost:8080/credential \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {}" \
  -d '{{
    "formats": ["jwt_vc_json", "sd_jwt_vc"],
    "types": ["VerifiableCredential", "UniversityDegreeCredential"],
    "proof": {{
      "proof_type": "jwt",
      "jwt": "{}"
    }}
  }}'"#,
        test_token, test_proof_jwt
    );

    HttpServer::new(|| {
        App::new()
            .service(handlers::credential_endpoint)
            .service(handlers::metadata_endpoint)
    })
    .bind(config::SERVER_ADDRESS)?
    .run()
    .await
}
