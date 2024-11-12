use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    alg: String,
}

impl Jwk {
    pub fn test() -> Self {
        Self {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "thisistestjwkx".to_string(),
            y: "thisistestjwky".to_string(),
            alg: "ES256".to_string(),
        }
    }

    pub fn _create_from_public_key(x_bytes: &[u8], y_bytes: &[u8]) -> Self {
        let x = URL_SAFE_NO_PAD.encode(x_bytes);
        let y = URL_SAFE_NO_PAD.encode(y_bytes);

        Self {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
            alg: "ES256".to_string(),
        }
    }
}
