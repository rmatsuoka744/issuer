// src/config.rs
use std::collections::HashMap;

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

/// テスト用のクライアントIDとシークレットのペアを取得する関数
fn client_secrets() -> HashMap<&'static str, &'static str> {
    let mut clients = HashMap::new();
    clients.insert("TEST_CLIENT_ID_1", "TEST_SECRET_1");
    clients.insert("TEST_CLIENT_ID_2", "TEST_SECRET_2");
    clients.insert("TEST_CLIENT_ID_3", "TEST_SECRET_3");
    clients
}

pub fn get_client_secret(client_id: &str) -> Option<&'static str> {
    client_secrets().get(client_id).copied()
}