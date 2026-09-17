# syntax=docker/dockerfile:1
#
# dldw 服务端镜像：单容器包含 dldw + sing-box + localfs 存储
# （容器内自动编排，无需额外安装）
#
# 构建：  docker build -t dldw:latest .
# 运行：  docker run -d -p 8080:8080 -p 8081:8081 -v dldw-data:/data dldw:latest
# 配置：  挂载 /data/server.yaml（模板见 deploy/server.example.yaml）

FROM golang:1.26-alpine AS build
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

# sing-box 阶段：从 GitHub Release 下载二进制（国内网络可换源：见 ARG SINGBOX_MIRROR）
FROM alpine:3.20 AS singbox
ARG SINGBOX_VERSION=1.14.1
ARG SINGBOX_MIRROR=https://github.com/SagerNet/sing-box/releases/download
RUN apk add --no-cache curl && \
    curl -sL --retry 5 -o /tmp/sb.tar.gz \
      "${SINGBOX_MIRROR}/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz" && \
    tar xzf /tmp/sb.tar.gz -C /tmp && \
    cp /tmp/sing-box-*/sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box

FROM alpine:3.20
RUN adduser -D -u 10001 dldw && apk add --no-cache ca-certificates
COPY --from=build /out/dldw /usr/local/bin/dldw
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
USER dldw
ENV DLDW_HOME=/data
VOLUME ["/data"]
# 8080 控制 API（含全部镜像端点）
# 8081 DLDW/1 隧道
# 9100 localfs 预签名下载（S3/Garage 部署时不需要）
EXPOSE 8080 8081 9100
ENTRYPOINT ["dldw"]
CMD ["serve", "--config", "/data/server.yaml"]
