#!/usr/bin/env bash
# Append audit log entry as JSON lines, secure permissions

AUDIT_LOG_FILE="audit.log"
touch "$AUDIT_LOG_FILE"
chmod 600 "$AUDIT_LOG_FILE"

log_audit_entry() {
  local username="$1"
  local user_action="$2"
  local log_entry="$3"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$timestamp\",\"user\":\"$username\",\"action\":\"$user_action\",\"entry\":\"$log_entry\"}" >> "$AUDIT_LOG_FILE"
}