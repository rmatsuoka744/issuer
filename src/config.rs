// サーバーアドレス
pub const SERVER_ADDRESS: &str = "127.0.0.1:8080";

// クレデンシャル発行者の情報
pub const CREDENTIAL_ISSUER: &str = "https://example.com";

// サポートされているクレデンシャルフォーマット
pub const SUPPORTED_FORMATS: [&str; 2] = ["jwt_vc_json", "sd_jwt_vc"];

// ノンスの有効期限（秒）
pub const NONCE_EXPIRATION: u64 = 300; // 5分