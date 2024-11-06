use crate::db::{get_secret_key_as_str, get_client_secret_by_id};
use lazy_static::lazy_static;

// サーバーアドレス
pub const SERVER_ADDRESS: &str = "127.0.0.1:8080";

// データベースから読み込む秘密鍵
lazy_static! {
    pub static ref ACCESS_TOKEN_SECRET: String = get_secret_key_as_str("ACCESS_TOKEN_SECRET")
        .expect("Failed to load ACCESS_TOKEN_SECRET");

    pub static ref CREDENTIAL_SECRET: String = get_secret_key_as_str("CREDENTIAL_SECRET")
        .expect("Failed to load CREDENTIAL_SECRET");

    pub static ref CLIENT_SECRET: String = get_secret_key_as_str("CLIENT_SECRET")
        .expect("Failed to load CLIENT_SECRET");
}

// クレデンシャル発行者の情報
pub const CREDENTIAL_ISSUER: &str = "https://example.com";

// サポートされているクレデンシャルフォーマット
pub const SUPPORTED_FORMATS: [&str; 2] = ["jwt_vc_json", "sd_jwt_vc"];

// ノンスの有効期限（秒）
pub const NONCE_EXPIRATION: u64 = 300; // 5分

/// クライアントIDに対応するシークレットを取得
pub fn get_client_secret(client_id: &str) -> Option<String> {
    get_client_secret_by_id(client_id) // db.rs の関数を呼び出し、データベースから取得
}