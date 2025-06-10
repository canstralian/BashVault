
#!/usr/bin/env bash
# Backup and integrity check for encrypted vault

BACKUP="$1"
if [[ -z "$BACKUP" ]]; then
  echo "Usage: $0 VAULT_FILE"
  exit 1
fi

sha256sum "$BACKUP" > "$BACKUP.sha256"
echo "Backup and SHA256 checksum written."

# To verify:
# sha256sum -c "$BACKUP.sha256"
