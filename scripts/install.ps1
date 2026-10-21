<#
  Rahro one-line installer (Windows Server).

  Panel:
    irm https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.ps1 | iex

  Node / tunnel (pass args):
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.ps1))) node   <code> -Panel https://PANEL:2053
    & ([scriptblock]::Create((irm .../install.ps1))) tunnel <code> -Panel https://PANEL:2053

  Builds from source with Go (install Go first: https://go.dev/dl/) and
  registers a Windows service.
#>
param(
  [string]$Mode = "panel",
  [string]$Code = "",
  [string]$Panel = "",
  [switch]$Insecure
)
$ErrorActionPreference = "Stop"
$Repo   = $env:RAHRO_REPO; if (-not $Repo) { $Repo = "https://github.com/AwmiresGg/rahro-tunnel" }
$Prefix = "C:\Program Files\Rahro"
$Data   = "C:\ProgramData\Rahro"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  throw "Go is required. Install it from https://go.dev/dl/ and re-run."
}
New-Item -ItemType Directory -Force -Path $Prefix, $Data | Out-Null

$src = Join-Path $env:TEMP ("rahro-" + [guid]::NewGuid())
Write-Host "==> fetching source" -ForegroundColor Cyan
git clone --depth 1 $Repo $src 2>$null
$env:CGO_ENABLED = "0"

function Build($name) {
  Write-Host "==> building $name" -ForegroundColor Cyan
  Push-Location $src
  go build -trimpath -ldflags "-s -w" -o (Join-Path $Prefix "$name.exe") "./cmd/$name"
  Pop-Location
}

function Install-Service($name, $bin, $svcArgs) {
  sc.exe stop $name 2>$null | Out-Null
  sc.exe delete $name 2>$null | Out-Null
  $binPath = "`"$bin`" $svcArgs"
  New-Service -Name $name -BinaryPathName $binPath -DisplayName $name -StartupType Automatic | Out-Null
  Start-Service $name
}

switch ($Mode) {
  "panel" {
    Build "rahro-panel"
    $cfg = Join-Path $Data "panel.json"
    $ip  = (Invoke-RestMethod "https://api.ipify.org")
    if (-not (Test-Path $cfg)) {
@"
{
  "log_level": "info",
  "panel": {
    "enabled": true,
    "listen": "0.0.0.0:2053",
    "tls_mode": "self-signed",
    "db_path": "$($Data -replace '\\','/')/rahro-panel.db",
    "public_url": "https://$ip:2053"
  }
}
"@ | Set-Content -Encoding UTF8 $cfg
    }
    $pass = -join ((48..57)+(97..122) | Get-Random -Count 12 | ForEach-Object {[char]$_})
    & (Join-Path $Prefix "rahro-panel.exe") admin create -config $cfg -u admin -p $pass 2>$null
    Install-Service "RahroPanel" (Join-Path $Prefix "rahro-panel.exe") "run -config `"$cfg`""
    Write-Host "`nRahro panel is up:  https://$ip:2053" -ForegroundColor Green
    Write-Host "Login: admin / $pass" -ForegroundColor Green
  }
  { $_ -in "node","tunnel" } {
    if (-not $Code -or -not $Panel) { throw "usage: install.ps1 $Mode <code> -Panel <url> [-Insecure]" }
    Build "rahro-node"
    $node = Join-Path $Data "node.json"
    $extra = @("enroll", $Code, "-panel", $Panel, "-out", $node)
    if ($Insecure) { $extra += "-insecure" }
    & (Join-Path $Prefix "rahro-node.exe") @extra
    Install-Service "RahroNode" (Join-Path $Prefix "rahro-node.exe") "run -config `"$node`""
    Write-Host "Rahro node ($Mode) enrolled and running." -ForegroundColor Green
  }
  default { throw "unknown mode '$Mode'" }
}
