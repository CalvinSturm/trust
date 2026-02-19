#!/usr/bin/env bash
set -euo pipefail

HOST_NAME="dev.calvinbuild.c2pa_inspect"
BINARY=""
EXTENSION_ID=""
MANIFEST_DIR=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  echo "Usage: $0 --binary <path> --extension-id <id> [--host-name <name>] [--manifest-dir <dir>]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-name)
      HOST_NAME="$2"
      shift 2
      ;;
    --binary)
      BINARY="$2"
      shift 2
      ;;
    --binary-path)
      BINARY="$2"
      shift 2
      ;;
    --extension-id)
      EXTENSION_ID="$2"
      shift 2
      ;;
    --manifest-dir)
      MANIFEST_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$BINARY" || -z "$EXTENSION_ID" ]]; then
  usage
  exit 2
fi

if command -v realpath >/dev/null 2>&1; then
  ABS_BIN="$(realpath "$BINARY")"
else
  ABS_BIN="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi

if [[ ! -f "$ABS_BIN" ]]; then
  echo "Binary not found: $ABS_BIN" >&2
  exit 1
fi

if [[ -n "$MANIFEST_DIR" ]]; then
  BASE_DIR="$MANIFEST_DIR"
elif [[ "$OSTYPE" == darwin* ]]; then
  BASE_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
else
  BASE_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
fi

mkdir -p "$BASE_DIR"
MANIFEST_PATH="$BASE_DIR/$HOST_NAME.json"
if [[ "$OSTYPE" == darwin* ]]; then
  TEMPLATE_PATH="$ROOT_DIR/assets/native-host-manifests/chrome_native_host_manifest.macos.template.json"
else
  TEMPLATE_PATH="$ROOT_DIR/assets/native-host-manifests/chrome_native_host_manifest.linux.template.json"
fi

if [[ ! -f "$TEMPLATE_PATH" ]]; then
  echo "Template not found: $TEMPLATE_PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to render native host manifest template" >&2
  exit 1
fi

python3 - "$TEMPLATE_PATH" "$HOST_NAME" "$ABS_BIN" "$EXTENSION_ID" "$MANIFEST_PATH" <<'PY'
import json
import pathlib
import sys

template_path, host_name, binary_path, extension_id, out_path = sys.argv[1:6]
text = pathlib.Path(template_path).read_text(encoding="utf-8")
text = text.replace("__HOST_NAME__", host_name)
text = text.replace("__BINARY_PATH__", binary_path)
text = text.replace("__EXTENSION_ID__", extension_id)
obj = json.loads(text)
pathlib.Path(out_path).write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
PY

echo "Installed native host manifest: $MANIFEST_PATH"
echo "Next: reload extension at chrome://extensions"
