
# Security Scripts Collection

This directory contains security utility scripts for enhanced password management and encryption capabilities.

## Scripts Overview

### 1. encrypt_decrypt_aes256gcm.sh
- **Purpose**: AES-256-GCM encryption/decryption with proper nonce and authentication tag handling
- **Usage**: `./encrypt_decrypt_aes256gcm.sh encrypt|decrypt KEY_FILE INPUT OUTPUT`
- **Features**: 
  - Secure nonce generation
  - Authentication tag verification
  - Hex-encoded output format

### 2. argon2_key_derivation.sh
- **Purpose**: Argon2 key derivation for password-based encryption
- **Usage**: `./argon2_key_derivation.sh PASSWORD SALT`
- **Features**: 
  - Memory-hard key derivation
  - Configurable parameters (time, memory, parallelism)

### 3. clipboard_util.sh
- **Purpose**: Cross-platform clipboard operations with auto-clear
- **Usage**: Source the script and call `copy_to_clipboard "data"`
- **Features**: 
  - Multi-platform support (macOS, Linux, Windows, Wayland)
  - Automatic clipboard clearing after 10 seconds

### 4. audit_log.sh
- **Purpose**: Secure audit logging with JSON format
- **Usage**: Source the script and call `log_audit "user" "action" "entry"`
- **Features**: 
  - JSON-formatted log entries
  - Secure file permissions (600)
  - ISO 8601 timestamps

### 5. backup_integrity_check.sh
- **Purpose**: Create backups with SHA256 integrity verification
- **Usage**: `./backup_integrity_check.sh VAULT_FILE`
- **Features**: 
  - SHA256 checksum generation
  - Integrity verification support

### 6. migration_password_expiry.sql
- **Purpose**: SQLite schema migration for password expiry features
- **Usage**: Execute against your SQLite database
- **Features**: 
  - Password expiry date tracking
  - Password status management

## Security Features

- **Encryption**: AES-256-GCM with proper nonce handling
- **Key Derivation**: Argon2 memory-hard function
- **Audit Trail**: Comprehensive logging with secure permissions
- **Data Integrity**: SHA256 checksums for backup verification
- **Privacy**: Auto-clearing clipboard functionality

## Integration with InfoGather

These scripts can be integrated into the InfoGather web dashboard to enhance security features:

1. **Scan Result Encryption**: Encrypt sensitive scan results using AES-256-GCM
2. **Secure Authentication**: Use Argon2 for password hashing in user management
3. **Audit Logging**: Track all security-sensitive operations
4. **Data Export Security**: Secure clipboard operations for sensitive data
5. **Backup Security**: Encrypted backups with integrity verification

## Requirements

- OpenSSL (for encryption operations)
- argon2 CLI tool (for key derivation)
- Standard Unix utilities (xxd, sha256sum, etc.)
- Clipboard utilities (pbcopy/xclip/wl-copy/clip depending on platform)

## Security Considerations

- All scripts use secure temporary file handling
- File permissions are set to restrict access (600)
- Sensitive data is cleared from memory where possible
- Proper error handling and input validation
- Cross-platform compatibility maintained
