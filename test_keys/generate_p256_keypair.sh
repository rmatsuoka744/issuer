#!/bin/bash

# スクリプト引数を確認
if [ -z "$1" ]; then
  echo "Usage: $0 <key_name>"
  echo "Example: $0 my_key"
  exit 1
fi

# 引数から鍵名を取得
KEY_NAME=$1

# ファイル名を定義
PRIVATE_KEY_FILE="${KEY_NAME}_private.pem"
PUBLIC_KEY_FILE="${KEY_NAME}_public.pem"

# 秘密鍵（PKCS#8形式）の生成
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$PRIVATE_KEY_FILE"
if [ $? -ne 0 ]; then
  echo "Failed to generate private key."
  exit 1
fi
echo "Private key generated: $PRIVATE_KEY_FILE"

# 公開鍵の抽出
openssl pkey -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE"
if [ $? -ne 0 ]; then
  echo "Failed to generate public key."
  exit 1
fi
echo "Public key generated: $PUBLIC_KEY_FILE"

echo "Key pair generation complete."
