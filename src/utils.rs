use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use log::debug;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub alg: String,
    pub crv: String,
    pub x: String,
}

impl Jwk {
    // PEM形式の公開鍵をJWK形式に変換
    pub fn from_pem_to_jwk(pem: &str) -> Result<serde_json::Value, String> {
        debug!("From {:?} to Jwk ...", pem);
        // PEMのヘッダー/フッターを削除してBase64部分を抽出
        let lines: Vec<&str> = pem.lines().collect();
        let base64_lines: Vec<&str> = lines
            .iter()
            .filter(|line| !line.starts_with("-----")) // PEMヘッダーを無視
            .map(|line| *line)
            .collect();
        let base64_data = base64_lines.concat();
        debug!("Parse pem to {:?}", base64_data);

        // 標準のBase64形式でデコード
        let decoded = STANDARD
            .decode(&base64_data)
            .map_err(|e| format!("Failed to decode Base64: {}", e))?;

        debug!("Decoded pem to {:?}", decoded);

        // 公開鍵データを抽出
        if decoded.len() >= 44 && &decoded[0..2] == [0x30, 0x2a] {
            let public_key = &decoded[12..44]; // 公開鍵部分（BIT STRINGの中身）

            let jwk = json!({
                "kty": "OKP",
                "alg": "EdDSA",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(public_key), // 公開鍵をBase64URLエンコード
            });

            return Ok(jwk);
        }

        Err("Unsupported PEM format or invalid Ed25519 public key.".to_string())
    }

    // JWK形式の公開鍵をPEM形式に変換
    pub fn from_jwk_to_pem(jwk: &Value) -> Result<String, String> {
        // JSONからJWKフィールドを取得
        let kty = jwk
            .get("kty")
            .and_then(Value::as_str)
            .ok_or_else(|| "Missing or invalid 'kty' field.".to_string())?;

        let crv = jwk
            .get("crv")
            .and_then(Value::as_str)
            .ok_or_else(|| "Missing or invalid 'crv' field.".to_string())?;

        let x = jwk
            .get("x")
            .and_then(Value::as_str)
            .ok_or_else(|| "Missing or invalid 'x' field.".to_string())?;

        // JWKの形式を確認
        if kty != "OKP" || crv != "Ed25519" {
            return Err("Unsupported JWK format. Only OKP with Ed25519 is supported.".to_string());
        }

        // 公開鍵をBase64URLからデコード
        let public_key = URL_SAFE_NO_PAD.decode(x)
            .map_err(|e| format!("Failed to decode Base64URL: {}", e))?;

        // ASN.1構造を作成
        let mut asn1 = vec![];
        asn1.extend_from_slice(&[0x30, 0x2a]); // SEQUENCE, 42バイト
        asn1.extend_from_slice(&[0x30, 0x05]); // SEQUENCE, 5バイト
        asn1.extend_from_slice(&[0x06, 0x03]); // OID, 3バイト
        asn1.extend_from_slice(&[0x2b, 0x65, 0x70]); // OID値: 1.3.101.112 (Ed25519)
        asn1.extend_from_slice(&[0x03, 0x21, 0x00]); // BIT STRING, 33バイト (未使用ビット数=0)
        asn1.extend_from_slice(&public_key); // 公開鍵データ

        // ASN.1をBase64エンコードしてPEM形式に変換
        let pem_body = STANDARD.encode(&asn1);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            pem_body
        );

        Ok(pem)
    }
}
