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

- **サンプルのclaim**
```json
{
    "vct": "https://credentials.example.com/identity_credential",
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US"
    },
    "birthdate": "1940-01-01",
    "is_over_18": true,
    "is_over_21": true,
    "is_over_65": true
}
```

- **レスポンス形式**:
```json
{
    "w3c_vc": {
        "format": "jwt_vc_json",
        "credential": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjYxMDk1MDYsImlhdCI6MTcyNjAyMzEwNiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN1YiI6IjkzZmRmNTk2LTdmNWQtNDRhMi1iMjRhLTYxMmJmNjVlNjRlNSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWRkcmVzcyI6eyJjb3VudHJ5IjoiVVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsInN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifSwiYmlydGhkYXRlIjoiMTk0MC0wMS0wMSIsImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJpc19vdmVyXzE4Ijp0cnVlLCJpc19vdmVyXzIxIjp0cnVlLCJpc19vdmVyXzY1Ijp0cnVlLCJwaG9uZV9udW1iZXIiOiIrMS0yMDItNTU1LTAxMDEiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.XvOr6SsOJ5APA7j1-KQA5ipdVNmgXzu3cZ1ZjQ91Yt0",
        "c_nonce": "504d048d-3536-4e8d-92ea-525a11b2859a",
        "c_nonce_expires_in": 300
    },
    "sd_jwt_vc": {
        "sd_jwt": "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJIUzI1NiJ9.eyJfc2QiOlsiU2pvRWFkUlluYkRydXNGZTBINTN6bk5MV0VMOVVIMnNBTDF3S2x4dFNCOCIsIkMxUkh5TC1zbjVvMG12UUJtZldCRXVoOENua2tVS0xlY2VMX0hzNHBOR2MiLCJVbFg5OUJaQllCck41VUQ2ZzR0cDdUXzRiZy1zUEtxd3ZMVEw2cml0YXlFIiwidEp4QnJFbXo4M09ETFlfMmE5MlBjSFZsQkxCNVZVQWxFc1Z6QW1DS0dWOCIsIl9nQ1FtQ3BDV0pGY3hhX2xldDBsZWhGT1Q0V2lnd3FyN1M0QV9mTVpjd2MiLCJZUnZteVZpbTV5YUM3bURWVmhoN1JXNjhVLXNqQkE1aTYwUUZhZWJrT2tJIiwiQVZCeTJHYWwwLURidS1DV0h3emZYQXJMUDlSQXFiR1FmMnRHQlJxRUl3dyIsIk9JLVFzdkVZaWtTX0YzdHZlX19ubEdrSHhTSE9scFlmaHhJYmpmR2ZvdWMiLCJ2VzRiZUo1UW9ZLVo1UkhlMUJMT3lJS1pRZDhjOUJVV0ZscmpZV3V1eDRBIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwiY25mIjp7Imp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCJ5IjoiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fSwiZXhwIjoxNzI2MTA5NTA2LCJpYXQiOjE3MjYwMjMxMDYsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJzdWIiOiJmMGM1Yjc5NS05OWUyLTQ3ODctOWFkZC00MzY0Yjk0MzJhMDgiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdfX0.WD9d68eowm9p0ILy2ZOpZ5Tjc5c6QB9XynYfd2VJOpA",
        "disclosures": [
            "WzUzYzViMjc5LWUzZjAtNDYzYy05NThjLTFkMjBkMzgxM2QwZiwgYWRkcmVzcywgeyJjb3VudHJ5IjoiVVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsInN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifV0",
            "WzUyZDUwNDUxLTgwNGUtNGNmMy1iMjU2LWZlYWQyNTliMzc3YywgYmlydGhkYXRlLCAiMTk0MC0wMS0wMSJd",
            "WzU0MjIyMjY3LWNmNjQtNGExOC1hMjk4LTJlNTAzMDk3YzZkZCwgZW1haWwsICJqb2huZG9lQGV4YW1wbGUuY29tIl0",
            "WzQ1YjQwYzE0LTFiMDQtNGQ0Yy05ZGFiLWY5NjBkOTNjZmQ4NiwgZmFtaWx5X25hbWUsICJEb2UiXQ",
            "W2ZkOWVjNzA3LWU1NjctNDM2NS05YjU2LWIxZDk1MWFhNWQyYiwgZ2l2ZW5fbmFtZSwgIkpvaG4iXQ",
            "WzMzM2FmZjRhLTYzZWItNDBjZi04ZjA3LTczNWQ1ZGQyYTUwOCwgaXNfb3Zlcl8xOCwgdHJ1ZV0",
            "W2E5NTg2MGU3LTlkOWUtNDE5Yy1hZTY3LWVkNGQ3MzZmZjM4YywgaXNfb3Zlcl8yMSwgdHJ1ZV0",
            "WzFkYjNkZjM2LTc2MTctNDYxNS1iMmIzLWVmMGU3MmE2ODZkYywgaXNfb3Zlcl82NSwgdHJ1ZV0",
            "WzY2ZGVlYTU5LWZkYTktNDJjMi1hNzY0LThiOThkZmI1YWZiZSwgcGhvbmVfbnVtYmVyLCAiKzEtMjAyLTU1NS0wMTAxIl0"
        ],
        "key_binding_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MjYwMjMxMDYsIm5vbmNlIjoiNTM5NzdiYzEtOWIyYy00MTAxLWI0MjctYWVkMzRmNTE0OTU4In0.Gml8Jt74LQMtjQhyxAEqXPm4edfonStAEtZTlodO2Bs"
    }
}
```

- **エンコード前の `w3c_vc credential`**:
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
{
  "exp": 1726109506,
  "iat": 1726023106,
  "iss": "https://example.com",
  "sub": "93fdf596-7f5d-44a2-b24a-612bf65e64e5",
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "credentialSubject": {
      "address": {
        "country": "US",
        "locality": "Anytown",
        "region": "Anystate",
        "street_address": "123 Main St"
      },
      "birthdate": "1940-01-01",
      "email": "johndoe@example.com",
      "family_name": "Doe",
      "given_name": "John",
      "is_over_18": true,
      "is_over_21": true,
      "is_over_65": true,
      "phone_number": "+1-202-555-0101",
      "vct": "https://credentials.example.com/identity_credential"
    },
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]
  }
}
```

- **エンコード前の `sd_jwt_vc sd_jwt`**:
```json
{
  "typ": "vc+sd-jwt",
  "alg": "HS256"
}
{
  "_sd": [
    "SjoEadRYnbDrusFe0H53znNLWEL9UH2sAL1wKlxtSB8",
    "C1RHyL-sn5o0mvQBmfWBEuh8CnkkUKLeceL_Hs4pNGc",
    "UlX99BZBYBrN5UD6g4tp7T_4bg-sPKqwvLTL6ritayE",
    "tJxBrEmz83ODLY_2a92PcHVlBLB5VUAlEsVzAmCKGV8",
    "_gCQmCpCWJFcxa_let0lehFOT4Wigwqr7S4A_fMZcwc",
    "YRvmyVim5yaC7mDVVhh7RW68U-sjBA5i60QFaebkOkI",
    "AVBy2Gal0-Dbu-CWHwzfXArLP9RAqbGQf2tGBRqEIww",
    "OI-QsvEYikS_F3tve__nlGkHxSHOlpYfhxIbjfGfouc",
    "vW4beJ5QoY-Z5RHe1BLOyIKZQd8c9BUWFlrjYWuux4A"
  ],
  "_sd_alg": "sha-256",
  "cnf": {
    "jwk": {
      "crv": "P-256",
      "kty": "EC",
      "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
      "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    }
  },
  "exp": 1726109506,
  "iat": 1726023106,
  "iss": "https://example.com",
  "sub": "f0c5b795-99e2-4787-9add-4364b9432a08",
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "vct": "https://credentials.example.com/identity_credential"
    },
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]
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

### 3. アクセストークン発行エンドポイント

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
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImV4cCI6MTcyNjAyNjYwMywiaWF0IjoxNzI2MDIzMDAzLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic2NvcGUiOiJjcmVkZW50aWFsX2lzc3VlIiwic3ViIjoieW91cl9jbGllbnRfaWQifQ.jOyDLyxXlVplYpPQdOJHveAC6cdIYDFHEuyXl7ytXO0",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "credential_issue",
    "c_nonce": "54f878c4-0047-475c-9cfd-4124ab0431c8",
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