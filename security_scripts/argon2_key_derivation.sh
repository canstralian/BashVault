
#!/usr/bin/env bash
# Argon2 key derivation prototype

PASSWORD="$1"
SALT="$2"
if [[ -z "$PASSWORD" || -z "$SALT" ]]; then
  echo "Usage: $0 PASSWORD SALT"
  exit 1
fi

# Generate Argon2 hash (raw output)
KEY=$(echo -n "$PASSWORD" | argon2 "$SALT" -r -t 2 -m 15 -p 1 -l 32)
echo "Derived key (hex): $KEY"
