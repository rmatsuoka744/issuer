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
  "formats": [
      "jwt_vc_json",
      "sd_jwt_vc"
  ],
  "types": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
  ],
  "proof": {
      "proof_type": "jwt",
      "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjQ4MzU2MzcsImlhdCI6MTcyNDgzMjAzNywibm9uY2UiOiJ0ZXN0X25vbmNlIn0.qV1zwmccUVhfVL-XTDhdDVlcxcJWPt8tdlhxoRAvtmw"
  }
}
```
- **レスポンス形式**:
```json
{
    "w3c_vc": {
        "format": "jwt_vc_json",
        "credential": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjQ5MTg0NDgsImlhdCI6MTcyNDgzMjA0OCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN1YiI6IjUzMjFiZjc1LWMxMWMtNGUwYS05YjI5LTBkNjhhMWRhM2FlMCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWRkcmVzcyI6eyJjb3VudHJ5IjoiVVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJTdGF0ZSIsInN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifSwiYmlydGhkYXRlIjoiMTk5MC0wMS0wMSIsImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2l2ZW5fbmFtZSI6IkpvaG4ifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.CIPdyzsCNFWZPkG4EWtlvaWsyTLR7owyIsaMOkXTGbI",
        "c_nonce": "15e95109-9268-40d4-bba5-90331248610c",
        "c_nonce_expires_in": 300
    },
    "sd_jwt_vc": {
        "sd_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJiaXJ0aGRhdGUiOiI1dUJuOV8ycXJtQWpIOUxrRGgzZGJueHZMM3JMaTBvTkFBb1B3VmIwREZ3IiwiZW1haWwiOiJqTXJQSGcwQXZ1eTFxbDl2R1JPNzhSNWx4ZFVjdkcxTXhlanFockl2ckVNIiwiZXhwIjoxNzI0OTE4NDQ4LCJmYW1pbHlfbmFtZSI6IkdLcXpNN19DcG9NSnY5QnF1SFNPQ0IyTndCUGNwekFPb2U5ZmRveHZsa28iLCJnaXZlbl9uYW1lIjoidzlrb1B4aldVNWd6N3h0Z3VNWGdfaEhXNnFVZUo1UnlYR2R0Y0xpR1JGRSIsImlhdCI6MTcyNDgzMjA0OCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN1YiI6IjM4ZTU3ZTU0LWRlMDgtNGE5Zi1hOWY1LTI3NzI5NjZlMGNiOCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.DTE-xM_-9zOF1ZTzBenQVuEd_pIp4kSlbAjrGYklzwg",
        "disclosures": [
            "W2IzZDBmNTM2LTAxODgtNDIwMS1hN2ExLTU4NWZkZWYwODBhZiwgYmlydGhkYXRlLCAxOTkwLTAxLTAxXQ",
            "WzU0MGU2OTZiLTJjMDMtNDA2YS05MzNhLWEyYTJlM2IzYzNjOSwgZW1haWwsIGpvaG5kb2VAZXhhbXBsZS5jb21d",
            "W2FiOGE1M2MzLTUzNjEtNDE5OS1hMDJhLTQ4YmIzMzI5N2U2YSwgZmFtaWx5X25hbWUsIERvZV0",
            "WzVkMTdlNTljLWQxNjQtNGIxMC04MjM5LWExNjk4NWU5ZmViMiwgZ2l2ZW5fbmFtZSwgSm9obl0"
        ],
        "key_binding_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MjQ4MzIwNDgsIm5vbmNlIjoiMWE0MmJmNmYtZjEzMy00ZmJhLTkwODMtNWE2ZjczMjkzZmI5In0.lmY91nfy4i-uScM5V9HC-HJSfaxz7z19PV8347lsFKg"
    }
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
            "types": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ]
        },
        {
            "format": "sd_jwt_vc",
            "types": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ]
        }
    ]
}
```

### 2. アクセストークン発行エンドポイント

- **URL**: `/token`
- **メソッド**: POST
- **説明**: 提供されたリクエストに基づいてAccess Tokenを発行します.
- **リクエスト形式**:
```json
{
    "grant_type": "client_credentials",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret",
    "scope": "credential_issue"
}
```

- **レスポンス形式**:
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImV4cCI6MTcyNTYwNzIxMiwiaWF0IjoxNzI1NjAzNjEyLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic2NvcGUiOiJjcmVkZW50aWFsX2lzc3VlIiwic3ViIjoieW91cl9jbGllbnRfaWQifQ.nFhZPR7nUMjbRPsHual47fY6W0wVXH-CNtTPSiya6R8",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "credential_issue",
    "c_nonce": "baf22316-ee32-41c7-81a5-b6cf52515cc9",
    "c_nonce_expires_in": 300
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