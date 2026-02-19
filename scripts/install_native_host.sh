#!/usr/bin/env bash
set -euo pipefail

HOST_NAME="dev.calvinbuild.c2pa_inspect"
BINARY_PATH=""
EXTENSION_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-name)
      HOST_NAME="$2"
      shift 2
      ;;
    --binary-path)
      BINARY_PATH="$2"
      shift 2
      ;;
    --extension-id)
      EXTENSION_ID="$2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$BINARY_PATH" || -z "$EXTENSION_ID" ]]; then
  echo "Usage: $0 --binary-path <path> --extension-id <id> [--host-name <name>]" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for absolute path resolution" >&2
  exit 1
fi

ABS_BIN="$(python3 - <<PY
import os,sys
print(os.path.abspath(sys.argv[1]))
PY
"$BINARY_PATH")"

if [[ ! -f "$ABS_BIN" ]]; then
  echo "Binary not found: $ABS_BIN" >&2
  exit 1
fi

if [[ "$OSTYPE" == darwin* ]]; then
  BASE_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
else
  BASE_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
fi

mkdir -p "$BASE_DIR"
MANIFEST_PATH="$BASE_DIR/$HOST_NAME.json"

cat > "$MANIFEST_PATH" <<JSON
{
  "name": "$HOST_NAME",
  "description": "C2PA inspect native host",
  "path": "$ABS_BIN",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXTENSION_ID/"
  ]
}
JSON

echo "Installed native host manifest: $MANIFEST_PATH"

