
#!/usr/bin/env bash
# Backup and integrity check for encrypted vault

VAULT_FILE_PATH="$1"
if [[ -z "$VAULT_FILE_PATH" ]]; then
  echo "Usage: $0 VAULT_FILE"
  exit 1
fi

sha256sum "$VAULT_FILE_PATH" > "$VAULT_FILE_PATH.sha256"
echo "Backup and SHA256 checksum written."

# To verify:
# sha256sum -c "$VAULT_FILE_PATH.sha256"
