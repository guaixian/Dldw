# syntax=docker/dockerfile:1

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

FROM alpine:3.20
RUN adduser -D -u 10001 dldw && apk add --no-cache ca-certificates
COPY --from=build /out/dldw /usr/local/bin/dldw
USER dldw
ENV DLDW_HOME=/data
VOLUME ["/data"]
EXPOSE 8080 8081
ENTRYPOINT ["dldw"]
# 配置挂载到 /data（推荐带注释的 YAML：deploy/server.example.yaml）
CMD ["serve", "--config", "/data/server.yaml"]
