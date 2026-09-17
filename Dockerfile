# dldw 服务端镜像：单容器包含 dldw + sing-box + localfs 存储
# （容器内自动编排，无需额外安装）
#
# 构建：  docker build -t dldw:latest .
# 运行：  docker run -d -p 8080:8080 -p 8081:8081 -v dldw-data:/data dldw:latest
# 配置：  挂载 /data/server.yaml（模板见 deploy/docker-server.example.yaml）
#
# 注意：sing-box-linux 需在宿主机预先下载（国内网络 Hub 拉不动）：
#   curl -L -o sb.tar.gz https://github.com/SagerNet/sing-box/releases/download/v1.14.1/sing-box-1.14.1-linux-amd64.tar.gz
#   tar xzf sb.tar.gz && cp sing-box-*/sing-box deploy/compose/data/sing-box-linux

FROM golang:latest AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY scripts ./scripts
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X dldw/internal/version.Version=${VERSION} -X dldw/internal/version.Commit=${COMMIT}" \
    -o /out/dldw ./cmd/dldw

FROM docker.m.daocloud.io/library/ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -u 10001 dldw
COPY --from=build /out/dldw /usr/local/bin/dldw
COPY deploy/compose/data/sing-box-linux /usr/local/bin/sing-box
RUN chmod +x /usr/local/bin/dldw /usr/local/bin/sing-box
USER dldw
ENV DLDW_HOME=/data
VOLUME ["/data"]
# 8080 控制 API（含全部镜像端点）
# 8081 DLDW/1 隧道
# 9100 localfs 预签名下载（S3/Garage 部署时不需要）
EXPOSE 8080 8081 9100
ENTRYPOINT ["dldw"]
CMD ["serve", "--config", "/data/server.yaml"]
