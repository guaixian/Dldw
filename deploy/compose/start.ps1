# dldw Docker 部署快速开始
#
# 用法：
#   1. 拷贝配置：cp deploy/docker-server.example.yaml deploy/compose/data/server.yaml
#   2. 编辑配置：填入 hysteria2 share_link、修改 secret
#   3. 启动：    cd deploy/compose && docker compose up -d
#   4. 客户端：  dldw config set server http://<宿主机IP>:8080 && dldw doctor --fix

param(
    [string]$ServerURL = "http://127.0.0.1:8080"
)
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent (Split-Path -Parent $dir)

# 1. 准备配置
$dataDir = Join-Path $dir "data"
if (-not (Test-Path (Join-Path $dataDir "server.yaml"))) {
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    Copy-Item (Join-Path $root "deploy\docker-server.example.yaml") (Join-Path $dataDir "server.yaml")
    Write-Host "[!] 已生成 $dataDir\server.yaml，请编辑填入 share_link 后重新运行" -ForegroundColor Yellow
    Write-Host "    notepad $dataDir\server.yaml"
    exit 1
}

# 2. 构建并启动
Write-Host "构建并启动 dldw-server..."
Push-Location $dir
docker compose up -d --build
Pop-Location

# 3. 等待就绪
Write-Host "等待服务就绪..."
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep 2
    try {
        $r = Invoke-RestMethod -TimeoutSec 3 "$ServerURL/readyz"
        if ($r.status -eq "ok") { $ok = $true; break }
    } catch {}
}
if ($ok) {
    Write-Host "[ok] dldw-server 运行中: $ServerURL" -ForegroundColor Green
    Write-Host ""
    Write-Host "客户端接入："
    Write-Host "  dldw config set server $ServerURL"
    Write-Host "  dldw doctor --fix"
} else {
    Write-Host "[FAIL] 服务未就绪，查看日志：docker logs dldw-server" -ForegroundColor Red
}
