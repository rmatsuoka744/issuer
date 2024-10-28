// src/config.rs

pub const SERVER_ADDRESS: &str = "127.0.0.1:8080";

// アクセストークンの秘密鍵（実際の環境では安全に管理された鍵を使用すること）
pub const ACCESS_TOKEN_SECRET: &str = "ACCESS_TOKEN_SECRET_KEY";

// クレデンシャル発行用の秘密鍵（実際の環境では安全に管理された鍵を使用すること）
pub const CREDENTIAL_SECRET: &str = "ISSUER_SECRET_KEY";

// クライアントの秘密鍵（実際の環境では安全に管理された鍵を使用すること）
pub const CLIENT_SECRET: &str = "CLIENT_SECRET_KEY";

// クレデンシャル発行者の情報
pub const CREDENTIAL_ISSUER: &str = "https://example.com";

// サポートされているクレデンシャルフォーマット
pub const SUPPORTED_FORMATS: [&str; 2] = ["jwt_vc_json", "sd_jwt_vc"];

// ノンスの有効期限（秒）
pub const NONCE_EXPIRATION: u64 = 300; // 5分
