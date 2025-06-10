#!/usr/bin/env bash
# Cross-platform clipboard copy and auto-clear

detect_clipboard_cmd() {
  if command -v pbcopy &>/dev/null; then
    echo "pbcopy"
  elif command -v xclip &>/dev/null; then
    echo "xclip -selection clipboard"
  elif command -v wl-copy &>/dev/null; then
    echo "wl-copy"
  elif [[ "$OS" == "Windows_NT" ]]; then
    echo "clip"
  else
    echo ""
  fi
}

copy_to_clipboard() {
  local data="$1"
  local CLIP_CMD
  CLIP_CMD=$(detect_clipboard_cmd)
  if [[ -z "$CLIP_CMD" ]]; then
    echo "No clipboard utility found."
    return 1
  fi
  echo -n "$data" | eval "$CLIP_CMD"
  # Clear clipboard after 10 seconds asynchronously
  (sleep 10; echo -n "" | eval "$CLIP_CMD") &
  echo "Copied to clipboard. Will auto-clear in 10 seconds."
}