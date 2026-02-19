param(
  [Parameter(Mandatory = $true)][string]$ExtensionId,
  [string]$Version = "latest",
  [string]$Repo = "CalvinSturm/trust",
  [string]$HostName = "dev.calvinbuild.c2pa_inspect"
)

$ErrorActionPreference = "Stop"

$platform = if ($IsWindows) { "windows" } elseif ($IsMacOS) { "macos" } else { "linux" }
$assetSuffix = if ($platform -eq "windows") { ".zip" } else { ".tar.gz" }
$targetToken = ""
switch ($platform) {
  "windows" { $targetToken = "pc-windows-msvc" }
  "macos" { $targetToken = "apple-darwin" }
  default { $targetToken = "unknown-linux-gnu" }
}

$baseApi = "https://api.github.com/repos/$Repo/releases"
$release = if ($Version -eq "latest") {
  Invoke-RestMethod -Uri "$baseApi/latest" -Headers @{"User-Agent"="trust-stack-installer"}
} else {
  $v = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
  Invoke-RestMethod -Uri "$baseApi/tags/$v" -Headers @{"User-Agent"="trust-stack-installer"}
}

$archive = $release.assets | Where-Object { $_.name -like "trust-stack-*${targetToken}*${assetSuffix}" } | Select-Object -First 1
if (-not $archive) {
  throw "Could not find release archive for target token '$targetToken'."
}
$checksums = $release.assets | Where-Object { $_.name -like "sha256sums-*.txt" } | Select-Object -First 1
if (-not $checksums) {
  throw "Could not find checksum asset."
}

$downloadDir = Join-Path $env:TEMP ("trust-stack-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
$archivePath = Join-Path $downloadDir $archive.name
$checksumsPath = Join-Path $downloadDir $checksums.name

Invoke-WebRequest -Uri $archive.browser_download_url -OutFile $archivePath
Invoke-WebRequest -Uri $checksums.browser_download_url -OutFile $checksumsPath

$hash = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$line = (Get-Content $checksumsPath | Where-Object { $_ -match [regex]::Escape($archive.name) } | Select-Object -First 1)
if (-not $line) {
  throw "Checksum entry missing for $($archive.name)."
}
$expected = ($line -split '\s+')[0].ToLowerInvariant()
if ($hash -ne $expected) {
  throw "Checksum mismatch for $($archive.name)."
}

$installRoot = Join-Path $env:LOCALAPPDATA "trust-stack"
$installDir = Join-Path $installRoot "bin"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

if ($archive.name.EndsWith(".zip")) {
  Expand-Archive -Path $archivePath -DestinationPath $installDir -Force
} else {
  throw "Unsupported archive format on this platform: $($archive.name)"
}

$nativeHostExe = Get-ChildItem -Path $installDir -Recurse -File | Where-Object { $_.Name -eq "c2pa-native-host.exe" } | Select-Object -First 1
if (-not $nativeHostExe) {
  throw "c2pa-native-host.exe not found after extraction."
}

$installerPath = Join-Path $PSScriptRoot "install_native_host.ps1"
& $installerPath -HostName $HostName -Binary $nativeHostExe.FullName -ExtensionId $ExtensionId
Write-Output "Installed native host binary: $($nativeHostExe.FullName)"
