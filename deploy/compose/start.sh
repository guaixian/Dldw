#!/usr/bin/env bash
# dldw Docker 部署快速开始（Linux/macOS）
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$DIR")")"
DATA_DIR="$DIR/data"

# 1. 准备配置
if [ ! -f "$DATA_DIR/server.yaml" ]; then
    mkdir -p "$DATA_DIR"
    cp "$ROOT/deploy/docker-server.example.yaml" "$DATA_DIR/server.yaml"
    echo "[!] 已生成 $DATA_DIR/server.yaml，请编辑填入 share_link 后重新运行"
    echo "    vi $DATA_DIR/server.yaml"
    exit 1
fi

# 2. 构建并启动
echo "构建并启动 dldw-server..."
cd "$DIR" && docker compose up -d --build

# 3. 等待就绪
echo "等待服务就绪..."
for i in $(seq 1 30); do
    sleep 2
    if curl -sf http://127.0.0.1:8080/readyz | grep -q '"ok"'; then
        echo "[ok] dldw-server 运行中: http://127.0.0.1:8080"
        echo ""
        echo "客户端接入："
        echo "  dldw config set server http://<宿主机IP>:8080"
        echo "  dldw doctor --fix"
        exit 0
    fi
done
echo "[FAIL] 服务未就绪，查看日志：docker logs dldw-server"
exit 1
