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
    "cnf": {
        "jwk": {
            "alg": "ES256",
            "crv": "P-256",
            "kty": "EC",
            "x": "thisistestjwkx",
            "y": "thisistestjwky"
        }
    },
    "proof": {
        "proof_type": "jwt",
        "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJleHAiOjE3MzE0OTAzNDQsImlhdCI6MTczMTQ4Njc0NCwibm9uY2UiOiJ0ZXN0X25vbmNlIn0.qSRo8opDgsqEQj182pRuPst2bYeBX2McwjOnGTozj5VF_IEPDVaDXY1nlirx0pFPVtV_GKZicwkhg1VSiqW0CQ"
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
        "credential": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJleHAiOjE3MzE1NzMyOTAsImlhdCI6MTczMTQ4Njg5MCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN1YiI6IjdmMDZkY2JhLTU4ZDItNGQyNS04ODNiLWNiNTg2ODI4OTcwYyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWRkcmVzcyI6eyJjb3VudHJ5IjoiVVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsInN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifSwiYmlydGhkYXRlIjoiMTk0MC0wMS0wMSIsImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJpc19vdmVyXzE4Ijp0cnVlLCJpc19vdmVyXzIxIjp0cnVlLCJpc19vdmVyXzY1Ijp0cnVlLCJwaG9uZV9udW1iZXIiOiIrMS0yMDItNTU1LTAxMDEiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.PA96UArjo_xH25-NGSgDOPQn3YQR8GxAveaNmgZerw7Igpn53W_wEuSOnDq783KDJUcXaXQJiMhH4izMXV3GBg",
        "c_nonce": "09ab3c88-0d3d-4850-9895-8d45bcf2b8b2",
        "c_nonce_expires_in": 300
    },
    "sd_jwt_vc": {
        "sd_jwt": "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJfc2QiOlsibEI1VzYzTWNKbVZVRVdKM3E4Smhjc0lWVmdWc1pUc0xZZXFPUTNaaEpaYyIsIk1rN0lET3dGMVoteF9CZHpjN0pLZmx3eU9hZnBzbG1BOGhhSEhhUGJLVmsiLCJTc3FhY18tR1FSYWhhVUtOdFFmVE1UZ1o3NmNkdVF5dDRwb0pNeVFFSWZVIiwiU2FHdHVfcXBjRENrZ1Z3LUVueV9iZWtXMm9Db2ZlRHIxaTBOeENjTHMtYyIsIk94MVZ6Ym44Qy1XMWNRN1VpSG44T3pkbEFjbW55bXRxSjRCZ0M4SEJzV3MiLCJXUUdvNnhLcWJXYUpteUpldUZQWEl5ZlRpU20zcEt1aHh2QktQbk5LbXFrIiwiUm54Ti1IR2FvMTRHczBROXI5ZVkxOTE0ZmZnOTVOWjNDRGp4YUhzTjFuOCIsInhPYUFSamlDQk1jUHdrM1lHSW5mVGZ0NHlKQXVhaUVZM0REZ3NEZ2NKR0EiLCJ5cTZGWElaTGJmYTBvSGY1NVNPR21mRWp0VzJxRVdqUTg2WTVpNk8zOExFIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwiY25mIjp7Imp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoidGhpc2lzdGVzdGp3a3giLCJ5IjoidGhpc2lzdGVzdGp3a3kifX0sImV4cCI6MTczMTU3MzI5MCwiaWF0IjoxNzMxNDg2ODkwLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiZDYzNzM5NjEtOGM5ZC00YjVhLTlkZWQtM2ZkMzI3M2ZiZDUzIiwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn0.mxDDs30C0-RDkLKiqTUt2eLD3Ntne32vlpy1dJQnlWxdnveqOXVCTHZSFJeIDGQbzgmz_mbvRoXxp1r1y16dCQ",
        "disclosures": [
            "WyJkYjVjODhmOS0wNjk1LTQwZjgtODI2MC0wYTk5MDBkYTBmMTEiLCAiYWRkcmVzcyIsIHsiY291bnRyeSI6IlVTIiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0In1d",
            "WyI4ZjViOGU5MC03MjcxLTRiNTYtYjg4Mi03OTJiNmMwZmQ0ODIiLCAiYmlydGhkYXRlIiwgIjE5NDAtMDEtMDEiXQ",
            "WyJhMTg5NWNjZS0yNmVmLTQxNmMtYTA4YS1hYzExYWU5Y2Q5YjQiLCAiZW1haWwiLCAiam9obmRvZUBleGFtcGxlLmNvbSJd",
            "WyJmOTc2N2E0Mi0yMWIyLTRiMjgtOTY3OC1kOWZhMjdmZDRjZWYiLCAiZmFtaWx5X25hbWUiLCAiRG9lIl0",
            "WyIxNzk2NGZhNS1jYTlkLTQ3MGMtYmMyZi1hOGZiNzUyZGI1ZDUiLCAiZ2l2ZW5fbmFtZSIsICJKb2huIl0",
            "WyI5YWRjOTg5OC0wZDIxLTQzODEtYjY4Yy01ZGI3NTJjMmU1OGUiLCAiaXNfb3Zlcl8xOCIsIHRydWVd",
            "WyI1MGRkNDU2Zi0zMzYyLTRmZmQtOTY3ZS1kY2ZhZmFmZTJjZTEiLCAiaXNfb3Zlcl8yMSIsIHRydWVd",
            "WyJlNzNiNjQ0ZS1lMzdiLTRjNGUtYmQ0Ny0zYjU2NzczOGU1MzAiLCAiaXNfb3Zlcl82NSIsIHRydWVd",
            "WyI5OTIwNGJmYi1iYWEyLTRlMjUtYTUyMC03NzdhZTBmNTdhZjUiLCAicGhvbmVfbnVtYmVyIiwgIisxLTIwMi01NTUtMDEwMSJd"
        ],
        "key_binding_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ0aGlzaXN0ZXN0andreCIsInkiOiJ0aGlzaXN0ZXN0andreSJ9fSwiaWF0IjoxNzMxNDg2ODkwLCJub25jZSI6Ijc5ZTMyNjZkLWEyOTktNDQyMy04OWNkLWJhN2EwMjgwNmRiOSJ9.RKHmUtEhWbgjUsgWFDqpCQlne2SFYi-7HLC5O-CJRePL9cIA8UWscuUK8zSwmmfFJYoFWKlRGtYvedkejcRrAQ"
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
    "exp": 1731573290,
    "iat": 1731486890,
    "iss": "https://example.com",
    "sub": "7f06dcba-58d2-4d25-883b-cb586828970c",
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
        "lB5W63McJmVUEWJ3q8JhcsIVVgVsZTsLYeqOQ3ZhJZc",
        "Mk7IDOwF1Z-x_Bdzc7JKflwyOafpslmA8haHHaPbKVk",
        "Ssqac_-GQRahaUKNtQfTMTgZ76cduQyt4poJMyQEIfU",
        "SaGtu_qpcDCkgVw-Eny_bekW2oCofeDr1i0NxCcLs-c",
        "Ox1Vzbn8C-W1cQ7UiHn8OzdlAcmnymtqJ4BgC8HBsWs",
        "WQGo6xKqbWaJmyJeuFPXIyfTiSm3pKuhxvBKPnNKmqk",
        "RnxN-HGao14Gs0Q9r9eY1914ffg95NZ3CDjxaHsN1n8",
        "xOaARjiCBMcPwk3YGInfTft4yJAuaiEY3DDgsDgcJGA",
        "yq6FXIZLbfa0oHf55SOGmfEjtW2qEWjQ86Y5i6O38LE"
    ],
    "_sd_alg": "sha-256",
    "cnf": {
        "jwk": {
            "alg": "ES256",
            "crv": "P-256",
            "kty": "EC",
            "x": "thisistestjwkx",
            "y": "thisistestjwky"
        }
    },
    "exp": 1731573290,
    "iat": 1731486890,
    "iss": "https://example.com",
    "sub": "d6373961-8c9d-4b5a-9ded-3fd3273fbd53",
    "vct": "https://credentials.example.com/identity_credential"
}
```

- **エンコード前の `key_binding_jwt`**:
```json
{
    "typ": "JWT",
    "alg": "EdDSA"
}
{
  "cnf": {
    "jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "kty": "EC",
      "x": "thisistestjwkx",
      "y": "thisistestjwky"
    }
  },
  "iat": 1731486890,
  "nonce": "79e3266d-a299-4423-89cd-ba7a02806db9"
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
    "client_id": "TEST_CLIENT_ID_1",
    "client_secret": "TEST_SECRET_1",
    "scope": "credential_issue"
}
```

- **レスポンス形式**:
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImV4cCI6MTczMTQ5MDQxMywiaWF0IjoxNzMxNDg2ODEzLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic2NvcGUiOiJjcmVkZW50aWFsX2lzc3VlIiwic3ViIjoiVEVTVF9DTElFTlRfSURfMSJ9.0CD6cAB48GtcT1FUP0oUiFXBBfJSSX-GUFdmdqt09FNYdTyM-eEsk5hagoAmbW49Y91uEBmtn1Ord3SAfmTpDg",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "credential_issue",
    "c_nonce": "1d1e49fc-02a3-4218-aa02-7e9a783e45c8",
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