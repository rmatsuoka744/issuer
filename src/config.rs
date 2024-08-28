// src/config.rs

pub const SERVER_ADDRESS: &str = "127.0.0.1:8080";

// JWT検証用の秘密鍵（実際の環境では安全に管理された鍵を使用すること）
pub const JWT_SECRET: &str = "your_secret_key_for_jwt_validation_and_signing";

// クレデンシャル発行者の情報
pub const CREDENTIAL_ISSUER: &str = "https://example.com";
pub const _CREDENTIAL_ENDPOINT: &str = "https://example.com/credential";

// サポートされているクレデンシャルフォーマット
pub const _SUPPORTED_FORMATS: [&str; 2] = ["jwt_vc_json", "ldp_vc"];

// ノンスの有効期限（秒）
pub const NONCE_EXPIRATION: u64 = 300; // 5分
