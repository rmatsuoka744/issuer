use rusqlite::{params, Connection, Result};
use std::sync::Mutex;
use lazy_static::lazy_static;
use log::debug;

lazy_static! {
    // データベース接続をグローバルに管理
    static ref DB_CONNECTION: Mutex<Connection> = Mutex::new(
        Connection::open("/home/rmatsuoka/Issuer/src/keys.db").expect("Failed to open database connection")
    );
}

/// データベースから指定された鍵名に基づいて秘密鍵を取得し、文字列として返す
pub fn get_secret_key_as_str(key_name: &str) -> Result<String> {
    let conn = DB_CONNECTION.lock().unwrap();
    let mut stmt = conn.prepare("SELECT key_value FROM keys WHERE key_name = ?1")?;
    let mut rows = stmt.query(params![key_name])?;

    if let Some(row) = rows.next()? {
        let key_value: String = row.get(0)?;
        // 鍵の読み出しに成功した場合のデバッグ出力
        debug!("Successfully retrieved key for '{}': {}", key_name, key_value);
        Ok(key_value)
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)
    }
}

/// データベースからクライアントIDに基づいてクライアントシークレットを取得
pub fn get_client_secret_by_id(client_id: &str) -> Option<String> {
    let conn = DB_CONNECTION.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT client_secret FROM client_keys WHERE client_id = ?1")
        .expect("Failed to prepare statement for client secret retrieval");

    let mut rows = stmt.query(params![client_id]).ok()?;
    if let Some(row) = rows.next().ok()? {
        let client_secret: String = row.get(0).ok()?;
        // クライアントシークレットの読み出しに成功した場合のデバッグ出力
        debug!("Successfully retrieved client secret for '{}': {}", client_id, client_secret);
        Some(client_secret)
    } else {
        None
    }
}