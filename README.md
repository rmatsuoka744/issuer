# Verifiable Credentials 発行サーバー

このプロジェクトは、OpenID for Verifiable Credential Issuance (OID4VCI)仕様とW3C Verifiable Credentials Data Modelに基づいて、Verifiable Credentials発行サーバーを実装しています。

## 準拠仕様

本実装は以下の仕様に準拠しています：

1. [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
2. [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
3. [draft-ietf-oauth-sd-jwt-vc-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-04)

## 主な機能

- JWT形式でのVerifiable Credentials発行
- Proof of Possessionを含むクレデンシャル要求のサポート
- ノンスベースのリプレイ攻撃防止機能の実装
- サポートされているクレデンシャルタイプに関するメタデータの提供

## エンドポイント

### 1. クレデンシャル発行エンドポイント

- **URL**: `/credential`
- **メソッド**: POST
- **説明**: 提供されたリクエストに基づいてVerifiable Credentialを発行します.`[INFO  Issuer] Test curl command:`以降をコピペすることでAPIのテストが可能です.
- **リクエスト形式**:
  ```json
  {
    "format": "jwt_vc_json",
    "types": ["VerifiableCredential", "UniversityDegreeCredential"],
    "proof": {
      "proof_type": "jwt",
      "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
    }
  }
  ```
- **レスポンス形式**:
  ```json
  {
    "format": "jwt_vc_json",
    "credential": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "c_nonce": "1234567890",
    "c_nonce_expires_in": 300
  }
  ```

### 2. メタデータエンドポイント

- **URL**: `/.well-known/openid-credential-issuer`
- **メソッド**: GET
- **説明**: クレデンシャル発行者に関するメタデータを提供します
- **レスポンス形式**:
  ```json
  {
    "credential_issuer": "https://example.com",
    "credential_endpoint": "https://example.com/credential",
    "credentials_supported": [
      {
        "format": "jwt_vc_json",
        "types": ["VerifiableCredential", "UniversityDegreeCredential"]
      }
    ]
  }
  ```

## セットアップと実行方法

1. RustとCargoがインストールされていることを確認してください
2. このリポジトリをクローンします
3. `cargo build`を実行してプロジェクトをコンパイルします
4. `cargo run`を実行してサーバーを起動します

デフォルトでは、サーバーは`http://localhost:8080`で起動します。

## テスト

サーバー起動時にログに表示されるcurlコマンドを使用して、クレデンシャル発行エンドポイントをテストできます。アクセストークンとProof JWTは、サーバー起動時に生成されたものに置き換えてください。

## セキュリティ上の考慮事項

この実装には、アクセストークンの検証やProof of Possessionの検証など、基本的なセキュリティ対策が含まれています。ただし、本番環境での使用には、以下のような追加のセキュリティ対策を実装する必要があります：

- 適切な鍵管理
- ノンスの安全な保存
- レート制限
- 入力の検証とサニタイズ

## 今後の改善点

- SD-JWTを含む複数のクレデンシャル形式のサポート
- アクセストークン発行のための完全なOAuth 2.0フローの実装
- エラーハンドリングとログ出力の強化
- 包括的なテストスイートの実装

## ライセンス

[ここにライセンスを指定してください]