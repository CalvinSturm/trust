#!/usr/bin/env bash
set -euo pipefail

EXTENSION_ID=""
VERSION="latest"
REPO="CalvinSturm/trust"
HOST_NAME="dev.calvinbuild.c2pa_inspect"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 --extension-id <id> [--version <latest|vX.Y.Z>] [--repo <owner/repo>] [--host-name <name>]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --extension-id)
      EXTENSION_ID="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --repo)
      REPO="$2"
      shift 2
      ;;
    --host-name)
      HOST_NAME="$2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$EXTENSION_ID" ]]; then
  usage
  exit 2
fi

if command -v uname >/dev/null 2>&1; then
  os_name="$(uname -s)"
else
  echo "Could not detect OS" >&2
  exit 1
fi

case "$os_name" in
  Darwin) target_token="apple-darwin" ;;
  Linux) target_token="unknown-linux-gnu" ;;
  *)
    echo "Unsupported OS for this installer: $os_name" >&2
    exit 1
    ;;
esac

api_base="https://api.github.com/repos/${REPO}/releases"
if [[ "$VERSION" == "latest" ]]; then
  release_json="$(curl -fsSL -H 'User-Agent: trust-stack-installer' "$api_base/latest")"
else
  tag="$VERSION"
  if [[ "$tag" != v* ]]; then
    tag="v${tag}"
  fi
  release_json="$(curl -fsSL -H 'User-Agent: trust-stack-installer' "$api_base/tags/${tag}")"
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for release metadata parsing" >&2
  exit 1
fi

readarray -t parsed < <(python3 - "$target_token" "$release_json" <<'PY'
import json
import sys

target = sys.argv[1]
release = json.loads(sys.argv[2])
archive = None
checksums = None
for a in release.get("assets", []):
    name = a.get("name", "")
    if target in name and name.startswith("trust-stack-") and name.endswith(".tar.gz"):
        archive = (name, a.get("browser_download_url", ""))
    if name.startswith("sha256sums-") and name.endswith(".txt"):
        checksums = (name, a.get("browser_download_url", ""))
if archive:
    print(archive[0])
    print(archive[1])
if checksums:
    print(checksums[0])
    print(checksums[1])
PY
)

if [[ ${#parsed[@]} -lt 4 ]]; then
  echo "Could not resolve archive/checksums for target $target_token" >&2
  exit 1
fi

archive_name="${parsed[0]}"
archive_url="${parsed[1]}"
checksums_name="${parsed[2]}"
checksums_url="${parsed[3]}"

work_dir="$(mktemp -d)"
archive_path="$work_dir/$archive_name"
checksums_path="$work_dir/$checksums_name"

curl -fsSL "$archive_url" -o "$archive_path"
curl -fsSL "$checksums_url" -o "$checksums_path"

if command -v sha256sum >/dev/null 2>&1; then
  actual_hash="$(sha256sum "$archive_path" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_hash="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
else
  echo "sha256sum or shasum required" >&2
  exit 1
fi

expected_hash="$(grep -F " $archive_name" "$checksums_path" | awk '{print $1}' | head -n1)"
if [[ -z "$expected_hash" ]]; then
  echo "Checksum entry missing for $archive_name" >&2
  exit 1
fi
if [[ "${actual_hash,,}" != "${expected_hash,,}" ]]; then
  echo "Checksum mismatch for $archive_name" >&2
  exit 1
fi

install_dir="$HOME/.local/share/trust-stack/bin"
mkdir -p "$install_dir"
tar -xzf "$archive_path" -C "$install_dir"

native_host_bin="$(find "$install_dir" -type f -name c2pa-native-host -print | head -n1)"
if [[ -z "$native_host_bin" ]]; then
  echo "c2pa-native-host not found after extraction" >&2
  exit 1
fi
chmod +x "$native_host_bin" || true

"$SCRIPT_DIR/install_native_host.sh" --host-name "$HOST_NAME" --binary "$native_host_bin" --extension-id "$EXTENSION_ID"
echo "Installed native host binary: $native_host_bin"
