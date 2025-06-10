#!/usr/bin/env bash
# Append audit log entry as JSON lines, secure permissions

AUDIT_FILE="audit.log"
touch "$AUDIT_FILE"
chmod 600 "$AUDIT_FILE"

log_audit() {
  local user="$1"
  local action="$2"
  local entry="$3"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$ts\",\"user\":\"$user\",\"action\":\"$action\",\"entry\":\"$entry\"}" >> "$AUDIT_FILE"
}