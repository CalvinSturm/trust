param(
  [string]$HostName = "dev.calvinbuild.c2pa_inspect",
  [Alias("BinaryPath")][Parameter(Mandatory = $true)][string]$Binary,
  [Parameter(Mandatory = $true)][string]$ExtensionId,
  [string]$ManifestDir
)

$ErrorActionPreference = "Stop"

$resolvedBin = (Resolve-Path $Binary).Path
if ([string]::IsNullOrWhiteSpace($ManifestDir)) {
  $manifestDir = Join-Path $env:LOCALAPPDATA "trust-stack\native-hosts"
} else {
  $manifestDir = $ManifestDir
}
New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
$manifestPath = Join-Path $manifestDir "$HostName.json"

$templatePath = Join-Path $PSScriptRoot "..\assets\native-host-manifests\chrome_native_host_manifest.win.template.json"
$templatePath = (Resolve-Path $templatePath).Path
$template = Get-Content -Raw -Path $templatePath
$escapedHost = (ConvertTo-Json $HostName -Compress).Trim('"')
$escapedPath = (ConvertTo-Json $resolvedBin -Compress).Trim('"')
$escapedExtension = (ConvertTo-Json $ExtensionId -Compress).Trim('"')
$manifest = $template.Replace("__HOST_NAME__", $escapedHost).Replace("__BINARY_PATH__", $escapedPath).Replace("__EXTENSION_ID__", $escapedExtension)

Set-Content -Path $manifestPath -Value $manifest -Encoding UTF8

$regPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "(default)" -Value $manifestPath

Write-Output "Installed native host manifest: $manifestPath"
Write-Output "Registered: $regPath"
Write-Output "Next: reload extension at chrome://extensions"
