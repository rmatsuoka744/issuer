use base64::engine::general_purpose::{self, STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters, Jwk, OctetKeyPairParameters,
    OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{decode_header, DecodingKey};
use log::debug;
use serde_json::json;

use crate::models::CredentialRequest;

/// PEM形式の公開鍵をJWK形式に変換（EdDSAまたはP-256をサポート）
pub fn from_pem_to_jwk(pem: &str) -> Result<Jwk, String> {
    debug!("Determining key type for PEM...");

    // PEMのヘッダー/フッターを削除してBase64部分を抽出
    let base64_data: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    // Base64デコード
    let decoded = general_purpose::STANDARD
        .decode(&base64_data)
        .map_err(|e| format!("Failed to decode Base64: {}", e))?;

    // キーの判定
    if decoded.len() >= 44 && &decoded[0..2] == [0x30, 0x2a] {
        debug!("Detected Ed25519 public key.");
        return from_pem_to_jwk_eddsa(pem);
    } else if decoded.len() >= 91 && &decoded[0..2] == [0x30, 0x59] {
        debug!("Detected P-256 public key.");
        return from_pem_to_jwk_p256(pem);
    } else {
        return Err("Unsupported key format. Could not detect Ed25519 or P-256.".into());
    }
}

/// JWKオブジェクトをserde_json::Valueに変換（EdDSAまたはP-256をサポート）
pub fn from_jwk_to_value(jwk: &Jwk) -> Result<String, String> {
    debug!("Converting JWK to serde_json::Value...");

    // 共通パラメータとアルゴリズムパラメータを判定
    match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(_) => {
            debug!("Detected Ed25519 key (OKP).");
            from_jwk_to_value_eddsa(jwk)
        }
        AlgorithmParameters::EllipticCurve(_) => {
            debug!("Detected P-256 key (EC).");
            from_jwk_to_value_p256(jwk)
        }
        _ => Err("Unsupported algorithm parameters in JWK.".to_string()),
    }
}

/// PEM形式の公開鍵をJWK形式に変換 (returns jsonwebtoken::jwk::Jwk)
fn from_pem_to_jwk_eddsa(pem: &str) -> Result<Jwk, String> {
    debug!("Converting PEM to JWK...");

    // PEMのヘッダー/フッターを削除してBase64部分を抽出
    let lines: Vec<&str> = pem.lines().collect();
    let base64_lines: Vec<&str> = lines
        .iter()
        .filter(|line| !line.starts_with("-----")) // PEMヘッダーを無視
        .map(|line| *line)
        .collect();
    let base64_data = base64_lines.concat();
    debug!("Base64 Data: {}", base64_data);

    // 標準のBase64形式でデコード
    let decoded = STANDARD
        .decode(&base64_data)
        .map_err(|e| format!("Failed to decode Base64: {}", e))?;
    debug!("Decoded Data: {:x?}", decoded);

    // 公開鍵専用のPEMデータを解析
    if decoded.len() >= 44 && &decoded[0..2] == [0x30, 0x2a] {
        // 公開鍵の長さが44バイト、ASN.1構造がEd25519公開鍵形式を示す場合
        let public_key = &decoded[12..44]; // 公開鍵はBIT STRINGの中身
        debug!("Extracted Public Key: {:x?}", public_key);

        // 公開鍵をBase64URLエンコード
        let x = URL_SAFE_NO_PAD.encode(public_key);

        // 共通パラメータを設定
        let common = CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature), // デジタル署名用途
            key_operations: None,                          // 特定の操作は指定しない
            algorithm: None,                               // アルゴリズム指定なし
            key_id: None,                                  // Key IDは任意
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        };

        // OctetKeyPairParametersを設定
        let params = OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair, // OKPタイプを指定
            curve: EllipticCurve::Ed25519,            // Ed25519曲線を指定
            x,                                        // 公開鍵データ
        };

        // JWKを作成
        let jwk = Jwk {
            common,
            algorithm: AlgorithmParameters::OctetKeyPair(params),
        };

        return Ok(jwk);
    }

    // デコード結果の長さとヘッダー情報を出力
    Err(format!(
        "Unsupported PEM format or invalid Ed25519 public key. Length: {}, Header: {:x?}",
        decoded.len(),
        &decoded.get(0..2).unwrap_or(&[])
    ))
}

/// PEM形式のP-256公開鍵をJWK形式に変換
fn from_pem_to_jwk_p256(pem: &str) -> Result<Jwk, String> {
    // PEMのヘッダー/フッターを削除してBase64部分を抽出
    let base64_data: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    // Base64デコード
    let decoded = general_purpose::STANDARD.decode(&base64_data).unwrap();

    // 公開鍵のx, y座標を抽出
    if decoded.len() < 91 {
        return Err("Invalid P-256 public key length".into());
    }
    let x_bytes = &decoded[27..59];
    let y_bytes = &decoded[59..91];

    // x, y座標をBase64URLエンコード
    let x = general_purpose::URL_SAFE_NO_PAD.encode(x_bytes);
    let y = general_purpose::URL_SAFE_NO_PAD.encode(y_bytes);

    // 共通パラメータを設定
    let common = CommonParameters {
        public_key_use: Some(PublicKeyUse::Signature),
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_chain: None,
        x509_sha1_fingerprint: None,
        x509_sha256_fingerprint: None,
    };

    // EllipticCurveKeyParametersを設定
    let params = EllipticCurveKeyParameters {
        key_type: jsonwebtoken::jwk::EllipticCurveKeyType::EC,
        curve: EllipticCurve::P256,
        x,
        y,
    };

    // JWKを作成
    let jwk = Jwk {
        common,
        algorithm: AlgorithmParameters::EllipticCurve(params),
    };

    Ok(jwk)
}

/// JWK形式の公開鍵をPEM形式に変換
pub fn from_jwk_to_pem(jwk: &Jwk) -> Result<String, String> {
    // 公開鍵を取得
    let (_kty, _crv, x) = {
        let common = &jwk.common;
        let algorithm = &jwk.algorithm;

        // 公開鍵の利用と曲線がEd25519であることを確認
        if common.public_key_use != Some(PublicKeyUse::Signature) {
            return Err("Unsupported 'use' field. Expected 'sig'.".to_string());
        }

        let octet_params = match algorithm {
            AlgorithmParameters::OctetKeyPair(params) => params,
            _ => return Err("Unsupported algorithm parameters. Expected OctetKeyPair.".to_string()),
        };

        if octet_params.key_type != OctetKeyPairType::OctetKeyPair {
            return Err("Unsupported key type. Expected 'OKP'.".to_string());
        }

        if octet_params.curve != EllipticCurve::Ed25519 {
            return Err("Unsupported curve. Expected 'Ed25519'.".to_string());
        }

        (
            octet_params.key_type,
            octet_params.curve.clone(),
            &octet_params.x,
        )
    };

    // 公開鍵をBase64URLからデコード
    let public_key = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| format!("Failed to decode Base64URL: {}", e))?;
    debug!("Decoded Public Key: {:x?}", public_key);

    // ASN.1構造を作成
    let mut asn1 = vec![];
    asn1.extend_from_slice(&[0x30, 0x2c]); // SEQUENCE, 44 bytes
    asn1.extend_from_slice(&[0x30, 0x0a]); // SEQUENCE, 10 bytes
    asn1.extend_from_slice(&[0x06, 0x08]); // OBJECT IDENTIFIER, 8 bytes
    asn1.extend_from_slice(&[0x2b, 0x65, 0x70]); // OID: 1.3.101.112 (Ed25519)
    asn1.extend_from_slice(&[0x03, 0x22, 0x00]); // BIT STRING, 34 bytes (未使用ビット数=0)
    asn1.extend_from_slice(&public_key); // 公開鍵データ (32 bytes)

    // ASN.1をBase64エンコードしてPEM形式に変換
    let pem_body = STANDARD.encode(&asn1);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        pem_body
    );

    Ok(pem)
}

/// JWKオブジェクトをserde_json::Valueに変換
fn from_jwk_to_value_eddsa(jwk: &Jwk) -> Result<String, String> {
    debug!("Converting JWK to serde_json::Value...");

    // 共通パラメータとアルゴリズムパラメータの確認
    let (kty, alg, crv, x, use_field) = {
        let common = &jwk.common;
        let algorithm = &jwk.algorithm;

        // 公開鍵の利用がSignatureであることを確認
        let use_field = match common.public_key_use {
            Some(PublicKeyUse::Signature) => "sig",
            Some(PublicKeyUse::Encryption) => "enc",
            _ => "",
        };

        // OctetKeyPairパラメータの確認
        let (kty, crv, x) = match algorithm {
            AlgorithmParameters::OctetKeyPair(params) => {
                // キータイプと曲線がOKPおよびEd25519であることを確認
                if params.key_type != OctetKeyPairType::OctetKeyPair {
                    return Err("Unsupported key type in JWK. Expected 'OKP'.".to_string());
                }

                if params.curve != EllipticCurve::Ed25519 {
                    return Err("Unsupported curve in JWK. Expected 'Ed25519'.".to_string());
                }

                (&params.key_type, params.curve.clone(), &params.x)
            }
            _ => {
                return Err(
                    "Unsupported algorithm parameters in JWK. Expected OctetKeyPair.".to_string(),
                )
            }
        };

        (kty, "EdDSA", crv, x, use_field)
    };

    // 公開鍵をBase64URLエンコード（既にエンコードされている可能性があるので確認）
    // ここでは既にエンコードされていると仮定
    let x_encoded = x.clone();

    // JSONオブジェクトを作成
    let jwk_json = json!({
        "kty": kty,
        "alg": alg,
        "crv": crv,
        "x": x_encoded,
        "use": use_field,
    });

    // 文字列として返す
    serde_json::to_string(&jwk_json).map_err(|e| format!("Error serializing JSON: {}", e))
}

/// P-256専用: JWKオブジェクトをserde_json::Valueに変換
fn from_jwk_to_value_p256(jwk: &Jwk) -> Result<String, String> {
    debug!("Converting P-256 JWK to serde_json::Value...");

    // 共通パラメータとアルゴリズムパラメータの確認
    let (kty, alg, crv, x, y, use_field) = {
        let common = &jwk.common;
        let algorithm = &jwk.algorithm;

        // 公開鍵の利用がSignatureであることを確認
        let use_field = match common.public_key_use {
            Some(PublicKeyUse::Signature) => "sig",
            _ => {
                return Err("Unsupported public key use in JWK. Expected 'sig'.".to_string());
            }
        };

        // EllipticCurveパラメータの確認
        let (kty, crv, x, y) = match algorithm {
            AlgorithmParameters::EllipticCurve(params) => {
                // キータイプと曲線がECおよびP-256であることを確認
                if params.key_type != jsonwebtoken::jwk::EllipticCurveKeyType::EC {
                    return Err("Unsupported key type in JWK. Expected 'EC'.".to_string());
                }

                if params.curve != EllipticCurve::P256 {
                    return Err("Unsupported curve in JWK. Expected 'P-256'.".to_string());
                }

                ("EC", "P-256", params.x.clone(), params.y.clone())
            }
            _ => {
                return Err(
                    "Unsupported algorithm parameters in JWK. Expected EllipticCurve.".to_string(),
                )
            }
        };

        (kty, "ES256", crv, x, y, use_field)
    };

    // JSONオブジェクトを作成
    let jwk_json = json!({
        "kty": kty,
        "alg": alg,
        "crv": crv,
        "x": x,
        "y": y,
        "use": use_field,
    });

    // 文字列として返す
    serde_json::to_string(&jwk_json).map_err(|e| format!("Error serializing JSON: {}", e))
}

pub fn get_decoding_key_from_jwk(body: &CredentialRequest) -> Result<DecodingKey, String> {
    // 1. cnfがSomeか確認してjwkを取得
    if let Some(cnf) = &body.cnf {
        if let Some(jwk_value) = cnf.get("jwk") {
            debug!("Extracted cnf.jwk: {:?}", jwk_value);

            // jwk_valueをJwkオブジェクトに変換
            let jwk: Jwk = serde_json::from_value(jwk_value.clone())
                .map_err(|e| format!("Failed to parse JWK from 'cnf.jwk': {}", e))?;
            return DecodingKey::from_jwk(&jwk)
                .map_err(|e| format!("Failed to create DecodingKey: {}", e));
        }
    }

    // 2. cnfにjwkがなければproof.jwtをデコードしてヘッダーからjwkを取得
    debug!("cnf.jwk not found. Attempting to extract jwk from proof.jwt header...");
    let header = decode_header(&body.proof.jwt)
        .map_err(|e| format!("Failed to decode JWT header: {}", e))?;
    if let Some(jwk) = header.jwk {
        debug!("Extracted jwk from proof.jwt header: {:?}", jwk);

        return DecodingKey::from_jwk(&jwk)
            .map_err(|e| format!("Failed to create DecodingKey: {}", e));
    }

    // 3. どちらからもjwkが見つからなければエラー
    Err("JWK not found in both 'cnf' and 'proof.jwt'".to_string())
}
