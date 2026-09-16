# Build dldw for all supported platforms (run from repo root).
$ErrorActionPreference = "Stop"

$version = if ($env:DLDW_VERSION) { $env:DLDW_VERSION } else { "1.0.0" }
$commit = git rev-parse --short HEAD 2>$null
if (-not $commit -or $LASTEXITCODE -ne 0) { $commit = "unknown" }
$date = (Get-Date -Format "yyyy-MM-dd")

$ldflags = "-s -w -X dldw/internal/version.Version=$version -X dldw/internal/version.Commit=$commit -X dldw/internal/version.Date=$date"

$out = "dist"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$targets = @(
    @{GOOS="windows"; GOARCH="amd64"; ext=".exe"},
    @{GOOS="linux";   GOARCH="amd64"; ext=""},
    @{GOOS="linux";   GOARCH="arm64"; ext=""},
    @{GOOS="darwin";  GOARCH="amd64"; ext=""},
    @{GOOS="darwin";  GOARCH="arm64"; ext=""}
)

foreach ($t in $targets) {
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $name = "dldw-$($t.GOOS)-$($t.GOARCH)$($t.ext)"
    Write-Host "building $name"
    go build -trimpath -ldflags $ldflags -o (Join-Path $out $name) ./cmd/dldw
    if ($LASTEXITCODE -ne 0) { throw "build failed for $name" }
}

Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
Write-Host "artifacts in $out\"
