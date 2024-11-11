# Verifiable Credentials 発行サーバー

このプロジェクトは、OpenID for Verifiable Credential Issuance (OID4VCI)仕様とW3C Verifiable Credentials Data Modelに基づいて、Verifiable Credentials発行サーバーを実装しています。

## 構成図

```mermaid
sequenceDiagram
    participant Holder
    participant Issuer
    participant Verifier

    Holder->>Issuer: 1. Request Access Token<br>(grant_type, client_id, client_secret, scope)
    Issuer->>Issuer: 2. Validate client_id and client_secret
    Issuer->>Holder: 3. Issue Access Token

    Holder->>Issuer: 4. Request SD-JWT-VC<br>(Access Token, Public Key (JWK), Claims)
    Issuer->>Issuer: 5. Hash Claims and Create SD-JWT
    Issuer->>Issuer: 6. Create Disclosure for each Claim
    Issuer->>Holder: 7. Return SD-JWT and Disclosures

    Holder->>Verifier: 8. Present SD-JWT and necessary Disclosures
    Verifier->>Verifier: 9. Verify JWT signature using JWK
    Verifier->>Verifier: 10. Hash Disclosure and compare with SD-JWT
    Verifier->>Holder: 11. Confirm Holder's claim
```

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
        "credential": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJleHAiOjE3MzEzNzc5NTYsImlhdCI6MTczMTI5MTU1NiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN1YiI6ImI5NGE3NjVjLTZiMzMtNGEyMC1iYzgxLTZhYTZiNjRmODZlMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWRkcmVzcyI6eyJjb3VudHJ5IjoiVVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsInN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifSwiYmlydGhkYXRlIjoiMTk0MC0wMS0wMSIsImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJpc19vdmVyXzE4Ijp0cnVlLCJpc19vdmVyXzIxIjp0cnVlLCJpc19vdmVyXzY1Ijp0cnVlLCJwaG9uZV9udW1iZXIiOiIrMS0yMDItNTU1LTAxMDEiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.wDKX00cJTuMBZvj__G54s1lZeAHbQhPByiW7tJpDLDFdO6IC3uGgeQzIoxd8bM8rhXcgU7M-akU6n00cOw4XDQ",
        "c_nonce": "0492023d-820c-4aa1-8c75-060bb5b2d13f",
        "c_nonce_expires_in": 300
    },
    "sd_jwt_vc": {
        "sd_jwt": "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJfc2QiOlsiTlFwUGVwazdEVTA0WHNQTUNOWUxHMm5qM1YxQlZzUG82RU1OSkVfWXFmWSIsIkl4N01UVXBDYWpzREEzVWdidEg5ek5VMG5lNmNUNm1KZzQwZXFSUDFEZFEiLCJRWHY1QWkzUmFMT2QtTHNOVzFYdWdJbWZjbVp1eFNqbmFsWHlqUVR1OEhjIiwiamoxME1meDh0TS1GZjJSeFNZRTNXYTBLdFg2Z1FfVnVGS1dld2QyZzNrQSIsImhJUWxzMnJ1d0FHZXRNdVI0NTZ2aUdRVHYxQUVBWFZSa194YlBwWnBJOWsiLCJMR1Badlo0SW1kZGNOWnMxNGtBXzNUOVhkQXpBWjFnQ2x1LW9hLVRnUTc0IiwibzJxbWxDRW0tUzVuVVZqUjhGSEhSNGhZbXJFSWZydGlMTEdYanhoOVkyWSIsIkVoczZtWnEyaWp5SWF1dlhSdzFBdGt5UEJKMVIxLWVNRnhIMnJZSkhia2ciLCI5bXVDdTE5RVhCTlE5dGVXZGpKTGxLamwyaUE1bGVYUjYxa1ZKcHI5dlBFIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwiY25mIjp7Imp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsInkiOiJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19LCJleHAiOjE3MzEzNzc5NTYsImlhdCI6MTczMTI5MTU1NiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN1YiI6IjAwMzYyMDNmLWM1NTktNGY5ZC1iNWQ0LTA5OWU2MTkxMmUwNCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.R-kjSDnSKNH7H1Jx48Br_ehHV_BIJTKRu08ULW8LHB3GJUVUMNAK4VSo4_-A9ljyya0fubbfFJcm6d9UvelpBw",
        "disclosures": [
            "WzkwYWNiOWIzLTc3NjItNDQwMS05MzZlLWE4MDJjODUyNzVmMSwgYWRkcmVzcywgeyJjb3VudHJ5IjoiVVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsInN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifV0",
            "Wzg0MDlkZDBkLTIzNGItNDQzYS1hYmU5LTE1YTZiOTIxMjk1YiwgYmlydGhkYXRlLCAiMTk0MC0wMS0wMSJd",
            "WzZkOWQ4OGYzLTVjYmMtNDYwYi1hMDEyLTUxZDc1MDJlMDQ2MCwgZW1haWwsICJqb2huZG9lQGV4YW1wbGUuY29tIl0",
            "W2I5YmQ5NWFjLTgwNzctNDE3Zi1iODMyLTBlZWFhNTU5NWM4MCwgZmFtaWx5X25hbWUsICJEb2UiXQ",
            "Wzk3M2VlMTU3LTM2M2YtNDQxOS05YjQ3LWIxMzYzZWY0MGI4NSwgZ2l2ZW5fbmFtZSwgIkpvaG4iXQ",
            "WzcyODZmODIwLWI0ZDMtNDAwYy1hY2MxLTIwODQzM2I1MWRiYSwgaXNfb3Zlcl8xOCwgdHJ1ZV0",
            "WzhhYzFhYTc5LTRmNjMtNGMxZC1iZDI1LTc5NTkwMWY5MmU3NCwgaXNfb3Zlcl8yMSwgdHJ1ZV0",
            "WzM1MGYxOTY2LTFkYTMtNGVmNy04Y2YyLWE4ZTNhZDBjNTcxMCwgaXNfb3Zlcl82NSwgdHJ1ZV0",
            "WzBjZmMwNDk0LWUyMGItNGNhOC1hMzI0LTVkZWI1YjVhZTBkMiwgcGhvbmVfbnVtYmVyLCAiKzEtMjAyLTU1NS0wMTAxIl0"
        ],
        "key_binding_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MzEyOTE1NTYsIm5vbmNlIjoiOThiZDQ2ZjEtZDdlMS00Yjk2LWEyOTktZGEzN2U4OWQxZTNlIn0.99aNkYIG-KzeQmHhwHZLST5xJkZQHGOJrbVaLcUCDE0oaBBnu_mXaZniV30SZNkwGSEo-PzM8NWxrKEgbEMEBg"
    }
}
```

- **エンコード前の `w3c_vc credential`**:
```json
{
    "typ": "JWT",
    "alg": "EdDSA"
}
{
    "exp": 1731377956,
    "iat": 1731291556,
    "iss": "https://example.com",
    "sub": "b94a765c-6b33-4a20-bc81-6aa6b64f86e3",
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
    "alg": "EdDSA"
}
{
    "_sd": [
        "NQpPepk7DU04XsPMCNYLG2nj3V1BVsPo6EMNJE_YqfY",
        "Ix7MTUpCajsDA3UgbtH9zNU0ne6cT6mJg40eqRP1DdQ",
        "QXv5Ai3RaLOd-LsNW1XugImfcmZuxSjnalXyjQTu8Hc",
        "jj10Mfx8tM-Ff2RxSYE3Wa0KtX6gQ_VuFKWewd2g3kA",
        "hIQls2ruwAGetMuR456viGQTv1AEAXVRk_xbPpZpI9k",
        "LGPZvZ4ImddcNZs14kA_3T9XdAzAZ1gClu-oa-TgQ74",
        "o2qmlCEm-S5nUVjR8FHHR4hYmrEIfrtiLLGXjxh9Y2Y",
        "Ehs6mZq2ijyIauvXRw1AtkyPBJ1R1-eMFxH2rYJHbkg",
        "9muCu19EXBNQ9teWdjJLlKjl2iA5leXR61kVJpr9vPE"
    ],
    "_sd_alg": "sha-256",
    "cnf": {
        "jwk": {
            "alg": "ES256",
            "crv": "P-256",
            "kty": "EC",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        }
    },
    "exp": 1731377956,
    "iat": 1731291556,
    "iss": "https://example.com",
    "sub": "0036203f-c559-4f9d-b5d4-099e61912e04",
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
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImV4cCI6MTczMTI5NTEzMSwiaWF0IjoxNzMxMjkxNTMxLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic2NvcGUiOiJjcmVkZW50aWFsX2lzc3VlIiwic3ViIjoiVEVTVF9DTElFTlRfSURfMSJ9._PYqG52lG0Gcko0633fvboJJfT3C63PeLgY10dQ2COAyg30szg4tbHDdk947PWk_pxwnGHgZhUXz_zd7-0j3Cw",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "credential_issue",
    "c_nonce": "be0c643b-e0f4-45f1-bc02-a8c2fcb6eba6",
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