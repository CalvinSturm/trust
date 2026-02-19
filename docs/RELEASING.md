# Releasing

## Pre-release checklist

1. Ensure workspace version in `Cargo.toml` (`[workspace.package].version`) is updated.
2. Run local gates:
   - `cargo fmt --all`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
3. Review `CHANGELOG.md` for the release entry.

## Cut a release tag

```bash
git checkout main
git pull --ff-only
git tag -a v0.1.0 -m "trust-stack v0.1.0"
git push origin v0.1.0
```

The release workflow validates that `vX.Y.Z` matches `Cargo.toml` workspace version.

## What the release workflow builds

On each `v*.*.*` tag:
- Builds on `ubuntu-latest`, `windows-latest`, `macos-latest`
- Produces per-OS archives with:
  - `toolfw`, `mcp-gateway`, `c2pa-inspect`, `c2pa-native-host`
  - `README.md`, license files
  - `docs/EXTENSION.md`
  - native-host install scripts
  - native-host manifest templates
- Produces `c2pa-inspect-extension-vX.Y.Z.zip`
- Produces `sha256sums-vX.Y.Z.txt`
- Uploads all assets to the GitHub Release

## Local artifact validation

After downloading release assets:

```bash
sha256sum -c sha256sums-vX.Y.Z.txt
```

On macOS without `sha256sum`:

```bash
shasum -a 256 trust-stack-vX.Y.Z-*.tar.gz c2pa-inspect-extension-vX.Y.Z.zip
```

On Windows PowerShell:

```powershell
Get-FileHash .\trust-stack-vX.Y.Z-*.zip -Algorithm SHA256
```

## Native host smoke test

1. Extract the archive.
2. Install host manifest using script (requires extension id):
   - PowerShell: `scripts/install_native_host.ps1 -Binary <path-to-c2pa-native-host(.exe)> -ExtensionId <id>`
   - Bash: `scripts/install_native_host.sh --binary <path-to-c2pa-native-host> --extension-id <id>`
3. Reload extension at `chrome://extensions`.
4. Right-click an image and run **Inspect Content Credentials**.
5. Verify result page returns a report or bounded error.
