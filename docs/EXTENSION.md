# C2PA Extension MVP

This repo includes a Chrome MV3 extension and a local Native Messaging host:

- Extension: `extensions/c2pa-inspect`
- Native host binary: `c2pa-native-host`
- Host name: `dev.calvinbuild.c2pa_inspect`

## Build Native Host

```bash
cargo build -p c2pa-native-host --release
```

Binary paths:
- Windows: `target\release\c2pa-native-host.exe`
- macOS/Linux: `target/release/c2pa-native-host`

## Install Extension (Chrome)

1. Open `chrome://extensions`
2. Enable Developer mode
3. Click **Load unpacked**
4. Select `extensions/c2pa-inspect/`

Usage:
- Right-click an image/link/video: **Inspect Content Credentials**
- Right-click page background: **Inspect primary media on this page**

## Native Host Manifest

Template:

```json
{
  "name": "dev.calvinbuild.c2pa_inspect",
  "description": "C2PA inspect native host",
  "path": "/absolute/path/to/c2pa-native-host",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://<YOUR_EXTENSION_ID>/"
  ]
}
```

The extension id appears on `chrome://extensions` after loading unpacked.

## Registration Paths

### Windows (Chrome)

Registry key:

`HKCU\Software\Google\Chrome\NativeMessagingHosts\dev.calvinbuild.c2pa_inspect`

Default value must be the absolute path to the manifest JSON.

### macOS

`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.calvinbuild.c2pa_inspect.json`

### Linux

`~/.config/google-chrome/NativeMessagingHosts/dev.calvinbuild.c2pa_inspect.json`

## Helper Scripts

### PowerShell

```powershell
./scripts/install_native_host.ps1 -HostName dev.calvinbuild.c2pa_inspect -BinaryPath ./target/release/c2pa-native-host.exe -ExtensionId <EXTENSION_ID>
```

### Bash

```bash
./scripts/install_native_host.sh --host-name dev.calvinbuild.c2pa_inspect --binary-path ./target/release/c2pa-native-host --extension-id <EXTENSION_ID>
```

Both scripts are idempotent and overwrite the manifest safely.

## Settings

Open extension options page and configure:
- `trust_mode`: `off` or `default`
- `max_download_bytes`: 1,000,000 to 200,000,000
- `timeout_ms`: 1,000 to 30,000

Settings are stored in Chrome sync storage (fallback local storage).

## Security Notes

- URL fetch only allows `http`/`https`.
- Fetch does not include cookies or browser auth headers.
- Download size caps and timeout caps are enforced.
- Host does not execute shell commands.
- Host does not log raw media bytes.

## Troubleshooting

- **No media detected**:
  The page may not expose visible `img/video poster/og:image` candidates. Try direct image right-click.
- **Blob/data URLs unsupported**:
  Only `http`/`https` media URLs are allowed.
- **Timed out / too large**:
  Increase timeout or max download bytes in extension settings.

## Manual Test Checklist

1. Right-click a page image and run **Inspect Content Credentials**.
2. Right-click page background and run **Inspect primary media on this page**.
3. Open options page, switch trust mode and caps, repeat inspection and verify behavior changes.
4. Confirm result page shows loading then report/error and supports Retry.
5. Confirm missing credentials show a gentle “may be stripped” hint.
