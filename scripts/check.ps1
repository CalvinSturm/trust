$ErrorActionPreference = "Stop"

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

$hasDeny = Get-Command cargo-deny -ErrorAction SilentlyContinue
if ($null -ne $hasDeny) {
    cargo deny check
} else {
    Write-Host "cargo-deny not found; skipping cargo deny check"
}
