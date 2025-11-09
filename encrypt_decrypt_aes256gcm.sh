#!/usr/bin/env bash
# AES-256-GCM encryption/decryption with nonce/tag handling

set -e

# Usage: ./encrypt_decrypt_aes256gcm.sh encrypt|decrypt KEY_FILE INPUT OUTPUT

CRYPTO_ACTION="$1"
ENCRYPTION_KEY_FILE="$2"
INPUT_FILE="$3"
OUTPUT_FILE="$4"

if [[ -z "$CRYPTO_ACTION" || -z "$ENCRYPTION_KEY_FILE" || -z "$INPUT_FILE" || -z "$OUTPUT_FILE" ]]; then
  echo "Usage: $0 encrypt|decrypt KEY_FILE INPUT OUTPUT"
  exit 1
fi

ENCRYPTION_KEY=$(xxd -p -c 256 "$ENCRYPTION_KEY_FILE" | tr -d '\n' | cut -c1-64)

if [[ "$CRYPTO_ACTION" == "encrypt" ]]; then
  ENCRYPTION_NONCE=$(openssl rand -hex 12)
  AUTHENTICATION_TAG_FILE=$(mktemp)
  openssl enc -aes-256-gcm -nosalt -K "$ENCRYPTION_KEY" -iv "$ENCRYPTION_NONCE" -in "$INPUT_FILE" -out "$OUTPUT_FILE.enc" -tag "$AUTHENTICATION_TAG_FILE"
  AUTHENTICATION_TAG_HEX=$(xxd -p "$AUTHENTICATION_TAG_FILE" | tr -d '\n')
  rm "$AUTHENTICATION_TAG_FILE"
  # Store as hex: nonce:tag:ciphertext
  echo -n "$ENCRYPTION_NONCE:$AUTHENTICATION_TAG_HEX:" > "$OUTPUT_FILE"
  cat "$OUTPUT_FILE.enc" | xxd -p | tr -d '\n' >> "$OUTPUT_FILE"
  rm "$OUTPUT_FILE.enc"
  echo "Encrypted and stored as: <nonce>:<tag>:<ciphertext> (hex)"
elif [[ "$CRYPTO_ACTION" == "decrypt" ]]; then
  IFS=':' read -r ENCRYPTION_NONCE AUTHENTICATION_TAG_HEX CIPHERTEXT_HEX < "$INPUT_FILE"
  CIPHERTEXT_BINARY_FILE=$(mktemp)
  echo -n "$CIPHERTEXT_HEX" | xxd -r -p > "$CIPHERTEXT_BINARY_FILE"
  AUTHENTICATION_TAG_FILE=$(mktemp)
  echo -n "$AUTHENTICATION_TAG_HEX" | xxd -r -p > "$AUTHENTICATION_TAG_FILE"
  openssl enc -d -aes-256-gcm -nosalt -K "$ENCRYPTION_KEY" -iv "$ENCRYPTION_NONCE" -in "$CIPHERTEXT_BINARY_FILE" -out "$OUTPUT_FILE" -tag "$AUTHENTICATION_TAG_FILE"
  rm "$CIPHERTEXT_BINARY_FILE" "$AUTHENTICATION_TAG_FILE"
  echo "Decrypted to $OUTPUT_FILE"
else
  echo "Unknown action: $CRYPTO_ACTION"
  exit 1
fi