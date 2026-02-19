param(
  [string]$HostName = "dev.calvinbuild.c2pa_inspect",
  [Parameter(Mandatory = $true)][string]$BinaryPath,
  [Parameter(Mandatory = $true)][string]$ExtensionId
)

$ErrorActionPreference = "Stop"

$resolvedBin = (Resolve-Path $BinaryPath).Path
$manifestDir = Join-Path $env:LOCALAPPDATA "trust-stack\native-hosts"
New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
$manifestPath = Join-Path $manifestDir "$HostName.json"

$manifest = @{
  name = $HostName
  description = "C2PA inspect native host"
  path = $resolvedBin
  type = "stdio"
  allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 4

Set-Content -Path $manifestPath -Value $manifest -Encoding UTF8

$regPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "(default)" -Value $manifestPath

Write-Output "Installed native host manifest: $manifestPath"
Write-Output "Registered: $regPath"

