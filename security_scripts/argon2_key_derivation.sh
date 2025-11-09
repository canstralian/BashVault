
#!/usr/bin/env bash
# Argon2 key derivation prototype

USER_PASSWORD="$1"
PASSWORD_SALT="$2"
if [[ -z "$USER_PASSWORD" || -z "$PASSWORD_SALT" ]]; then
  echo "Usage: $0 PASSWORD SALT"
  exit 1
fi

# Generate Argon2 hash (raw output)
DERIVED_KEY=$(echo -n "$USER_PASSWORD" | argon2 "$PASSWORD_SALT" -r -t 2 -m 15 -p 1 -l 32)
echo "Derived key (hex): $DERIVED_KEY"
