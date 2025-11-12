
#!/usr/bin/env bash
# Cross-platform clipboard copy and auto-clear

detect_clipboard_command() {
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
  local clipboard_data="$1"
  local clipboard_command
  clipboard_command=$(detect_clipboard_command)
  if [[ -z "$clipboard_command" ]]; then
    echo "No clipboard utility found."
    return 1
  fi
  echo -n "$clipboard_data" | eval "$clipboard_command"
  # Clear clipboard after 10 seconds asynchronously
  (sleep 10; echo -n "" | eval "$clipboard_command") &
  echo "Copied to clipboard. Will auto-clear in 10 seconds."
}
