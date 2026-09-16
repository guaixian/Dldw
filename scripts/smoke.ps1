# dldw end-to-end smoke test (Windows PowerShell 5.1)
# Usage: powershell -File scripts\smoke.ps1
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path $env:TEMP "opencode\dldw-smoke"
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

Write-Host "== building dldw"
$exe = Join-Path $tmp "dldw.exe"
go build -o $exe "$root\cmd\dldw"
if (-not $?) { throw "build failed" }

Write-Host "== starting test origin (127.0.0.1:19099, 4MiB artifact)"
$origin = Start-Process -FilePath "go" -ArgumentList "run","$root\scripts\origin","-addr","127.0.0.1:19099","-size","4194304" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

$apiPort = 19080
$tunnelPort = 19081
$originPort = 19099

# server config with loopback origin allowed (test-only)
$cfg = @"
{
  "listen": "127.0.0.1:$apiPort",
  "public_base": "http://127.0.0.1:$apiPort",
  "tunnel": {
    "enabled": true,
    "listen": "127.0.0.1:$tunnelPort",
    "max_conns_per_token": 8,
    "max_bytes_per_conn": "256MiB",
    "idle_timeout": "60s"
  },
  "storage": {"driver": "localfs", "root": "$($tmp -replace '\\','\\')\\objects", "secret": "smoke-test-secret-0123456789"},
  "executor": {"driver": "builtin", "ports": [$originPort], "allow_loopback": true},
  "auth": {"allow_registration": true},
  "data_dir": "$($tmp -replace '\\','\\')\\data"
}
"@
$cfgFile = Join-Path $tmp "server.json"
$cfg | Out-File -FilePath $cfgFile -Encoding ascii

Write-Host "== starting dldw serve"
$env:DLDW_HOME = Join-Path $tmp "home"
New-Item -ItemType Directory -Force -Path $env:DLDW_HOME | Out-Null
$server = Start-Process -FilePath $exe -ArgumentList "serve","--config",$cfgFile -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $tmp "server.out.log") -RedirectStandardError (Join-Path $tmp "server.log")
Start-Sleep -Seconds 2

try {
    Write-Host "== healthz"
    $h = Invoke-RestMethod "http://127.0.0.1:$apiPort/healthz"
    if ($h.status -ne "ok") { throw "healthz: $($h.status)" }

    Write-Host "== doctor --fix (registers device token)"
    & $exe --server "http://127.0.0.1:$apiPort" doctor --fix | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "doctor exited $LASTEXITCODE" }

    Write-Host "== dldw get (presigned fast path)"
    & $exe --server "http://127.0.0.1:$apiPort" get --chunk 512KiB --concurrency 4 "http://127.0.0.1:$originPort/org/repo/releases/download/v1/app.tar.gz" (Join-Path $tmp "app.tar.gz")
    if ($LASTEXITCODE -ne 0) { throw "get exited $LASTEXITCODE" }
    $f = Get-Item (Join-Path $tmp "app.tar.gz")
    if ($f.Length -ne 4194304) { throw "downloaded size $($f.Length) != 4194304" }

    Write-Host "== dldw get again (cache hit, zero origin transfer)"
    & $exe --server "http://127.0.0.1:$apiPort" get --chunk 512KiB "http://127.0.0.1:$originPort/org/repo/releases/download/v1/app.tar.gz" (Join-Path $tmp "app2.tar.gz")
    if ($LASTEXITCODE -ne 0) { throw "second get exited $LASTEXITCODE" }
    $f2 = Get-Item (Join-Path $tmp "app2.tar.gz")
    if ($f2.Length -ne 4194304) { throw "second download size mismatch" }

    Write-Host "== env output (powershell)"
    & $exe env --shell powershell | Select-Object -First 3 | ForEach-Object { Write-Host "  $_" }

    Write-Host "== version"
    & $exe version

    Write-Host "SMOKE TEST PASSED"
    exit 0
} finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    if ($origin -and -not $origin.HasExited) { Stop-Process -Id $origin.Id -Force }
    Get-Process -Name "origin" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
