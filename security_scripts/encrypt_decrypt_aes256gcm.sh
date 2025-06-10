
#!/usr/bin/env bash
# AES-256-GCM encryption/decryption with nonce/tag handling

set -e

# Usage: ./encrypt_decrypt_aes256gcm.sh encrypt|decrypt KEY_FILE INPUT OUTPUT

ACTION="$1"
KEY_FILE="$2"
INPUT="$3"
OUTPUT="$4"

if [[ -z "$ACTION" || -z "$KEY_FILE" || -z "$INPUT" || -z "$OUTPUT" ]]; then
  echo "Usage: $0 encrypt|decrypt KEY_FILE INPUT OUTPUT"
  exit 1
fi

KEY=$(xxd -p -c 256 "$KEY_FILE" | tr -d '\n' | cut -c1-64)

if [[ "$ACTION" == "encrypt" ]]; then
  NONCE=$(openssl rand -hex 12)
  TAG=$(mktemp)
  openssl enc -aes-256-gcm -nosalt -K "$KEY" -iv "$NONCE" -in "$INPUT" -out "$OUTPUT.enc" -tag "$TAG"
  TAG_HEX=$(xxd -p "$TAG" | tr -d '\n')
  rm "$TAG"
  # Store as hex: nonce:tag:ciphertext
  echo -n "$NONCE:$TAG_HEX:" > "$OUTPUT"
  cat "$OUTPUT.enc" | xxd -p | tr -d '\n' >> "$OUTPUT"
  rm "$OUTPUT.enc"
  echo "Encrypted and stored as: <nonce>:<tag>:<ciphertext> (hex)"
elif [[ "$ACTION" == "decrypt" ]]; then
  IFS=':' read -r NONCE TAG_HEX CIPHERTEXT_HEX < "$INPUT"
  CIPHERTEXT_BIN=$(mktemp)
  echo -n "$CIPHERTEXT_HEX" | xxd -r -p > "$CIPHERTEXT_BIN"
  TAG=$(mktemp)
  echo -n "$TAG_HEX" | xxd -r -p > "$TAG"
  openssl enc -d -aes-256-gcm -nosalt -K "$KEY" -iv "$NONCE" -in "$CIPHERTEXT_BIN" -out "$OUTPUT" -tag "$TAG"
  rm "$CIPHERTEXT_BIN" "$TAG"
  echo "Decrypted to $OUTPUT"
else
  echo "Unknown action: $ACTION"
  exit 1
fi
