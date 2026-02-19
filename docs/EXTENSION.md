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

## Security Notes

- URL fetch only allows `http`/`https`.
- Fetch does not include cookies or browser auth headers.
- Download size caps and timeout caps are enforced.
- Host does not execute shell commands.
- Host does not log raw media bytes.

