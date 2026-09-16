# dldw

低依赖、可审计、可回退的命令行下载加速与受控代理层。

**[English documentation](README.en.md)** · [完整技术方案](dldw_完整技术方案_去sing-box_v1.md)

## 概述

- **包装命令解决可达性**：`dldw git clone ...`、`dldw pip install ...` 经由临时本地代理运行；白名单域名走服务端隧道，其余直连，私网/保留段目标一律拒绝。
- **`dldw get` 解决大文件吞吐**：静态工件经服务端缓存抓取，以预签名 URL 从对象存储分块并发直传——缓存命中时服务端零字节中转。
- **拉穿镜像解决包生态**：PyPI / npm / Go modules / apt·yum / Docker Registry 各有协议感知的缓存（见下方能力矩阵），包装命令在用户未自配源时自动接入。
- **服务端是受控出口**：令牌认证、nonce 防重放、域名白名单、SSRF/防 DNS 重绑定、端口策略、限流、JSON 审计日志，以及可选的内嵌代理核心（自带 hysteria2 分享链接即可，服务端完全自包含）。

不使用 TUN / SOCKS / MITM；HTTPS 仅做 CONNECT 透传。纯 Go、零第三方依赖（sing-box 作为托管的子进程运行，不链接库）。

## 构建

```bash
# Windows / Linux / macOS 任一平台
go build ./cmd/dldw
# 全平台构建 + 版本号注入
scripts/build.sh          # Windows 用 scripts\build.ps1
# 单元 + 集成测试
go test ./...
# 二进制级端到端冒烟测试（服务端 + 源站 + get + doctor）
scripts/smoke.ps1
```

## 服务端快速开始

```bash
# 1. 拷贝带完整注释的配置模板并按需修改（每个字段都有说明）
cp deploy/server.example.yaml /etc/dldw/server.yaml
vi /etc/dldw/server.yaml
# 2. 白名单（同样带注释；保存即热加载）
cp deploy/whitelist.example.txt /etc/dldw/whitelist.txt
# 3. 启动
dldw serve --config /etc/dldw/server.yaml
# 端点：
#   http://127.0.0.1:8080  控制 API
#   http://127.0.0.1:8081  DLDW/1 隧道（生产环境请启用 TLS）
```

另有：`deploy/compose/docker-compose.yml`、`deploy/systemd/dldw.service`、根目录 `Dockerfile`。

### 存储驱动

| 驱动 | 说明 |
|---|---|
| `localfs`（默认，别名 `fs`） | 本地磁盘 + HMAC 预签名，由 `/files/` 提供断点下载 |
| `s3` | SigV4 预签名直传——AWS S3、阿里云 OSS、腾讯 COS、Cloudflare R2 等一切 S3 兼容后端，缓存命中流量零中转 |
| `minio` | 等价于 s3，强制 path-style（MinIO 寻址约定） |
| `openlist` | 把 OpenList/AList 挂载当作存储：S3 类挂载返回底层直链，本地/WebDAV 类挂载经 OpenList `/d/` 中转（Range 透传） |

执行器：`builtin`（默认，纯 Go 带重试）与 `aria2`（JSON-RPC）。

> 接入新存储后端：实现 `internal/transfer/storage.Storage` 接口（`PresignGet/PresignHead/Put/Head/Get/Delete/Ping`）并在 `app.New` 的 switch 中注册。`PresignGet` 返回的 URL 决定流量路径——直链等于零中转，代理 URL 等于中转。

## 客户端快速开始

```bash
dldw config init                 # 生成带完整注释的 ~/.dldw/config.yaml，按需编辑
dldw config set server https://dldw.example.com
dldw doctor --fix                # 注册设备令牌

dldw git clone https://github.com/org/repo.git
dldw curl -L -O https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw pip install -r requirements.txt
dldw uv sync                     # 自动注入本地 PyPI 镜像
dldw npm install                 # 自动注入本地 npm 镜像
dldw apt update                  # 默认只打印提示；root 且 --apply 才写 apt.conf.d
dldw docker pull nginx           # 检查 daemon.json 并给出配置指引

dldw get https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw get --concurrency 16 --chunk 32MiB URL out.tar.gz

dldw repo https://github.com/org/repo            # 仓库快照（tarball 永久缓存）
dldw repo https://github.com/org/repo/tree/dev d2

dldw benchmark --url URL --mode all
eval "$(dldw env)"               # PowerShell: dldw env --shell powershell | Invoke-Expression
```

### 配置文件

全部提供**带注释模板**，直接照着改：

- 客户端：`dldw config init` 生成 `~/.dldw/config.yaml`；`dldw config set` 写入的是 `~/.dldw/config.json`（一旦存在则优先生效），两者留一个即可。
- 服务端：`deploy/server.example.yaml`（每个字段含默认值、生产注意事项与端口约定）。
- 白名单：`deploy/whitelist.example.txt`（格式、匹配规则、热加载说明）。

配置优先级：`命令行 flags > 工具适配器 > 配置文件 > 默认值`。

> **端口约定（改端口前必读）**：客户端从 `server` URL 推导隧道地址——URL 带显式端口 `P` 时隧道端口为 `P+1`；`https://` 默认 4443，`http://` 默认 8081。修改服务端 `tunnel.listen` 时必须同步此约定。

## 命令面

| 命令 | 用途 |
|---|---|
| `dldw <工具> [参数...]` | 包装工具：本地代理 + 环境注入 + 适配器 + 镜像地址自动注入 |
| `dldw get <URL> [输出]` | 解析 → 预签名分块下载、断点续传、sha256 校验 |
| `dldw repo <git地址> [目录]` | 仓库快照：转 codeload tarball 缓存下载并安全解包 |
| `dldw env` | 输出常驻代理（`dldw proxy`）配套的环境变量 |
| `dldw doctor [--fix]` | 体检：端口、DNS、时钟、健康检查、令牌、白名单、存储、工具 |
| `dldw benchmark` | 直连 / 隧道 / 预签名 三模式的首字节与吞吐对比 |
| `dldw config` | init / show / set / unset / path |
| `dldw proxy` | 常驻本地代理（周期性刷新白名单） |
| `dldw serve [--no-proxy-core]` | 运行服务端（参数可临时禁用内嵌代理核心） |

全局参数（放在子命令之前）：`--server --token --profile --no-proxy --apply --direct-fallback/--no-direct-fallback --force-tunnel -v/-vv`。

## 架构

```
dldw <工具> ──> 本地 HTTP/CONNECT 代理 ──┬─ 白名单域名 ──> DLDW/1 隧道 ──> 服务端出口（SSRF/限流/审计）
                                         └─ 其余域名   ──> 直连（私网目标拒绝）
dldw get   ──> POST /api/v1/resolve ──> 命中：预签名 URL ──> 分块并发 GET（客户端 ↔ 对象存储）
                                 └─ 未命中：任务（queued→…→ready）──> refresh ──> 预签名下载
```

隧道协议：`DLDW/1 CONNECT <host> <port> <token> <nonce> <client_id> <flags>` → `DLDW/1 OK <conn_id> <expires_in> <resolved_ip>` / `DLDW/1 ERR <code> <msg>`，之后为裸 TCP 双向转发。

## 缓存能力矩阵（按层区分）

HTTP 层不可缓存不等于不可缓存：git 的 packfile 按协商生成、Docker 的认证令牌是动态的，
但 git 的对象（tarball）、Docker 的层（digest 内容寻址）都是不可变内容——下沉一层即可缓存。

| 工具 | HTTP 层 | 对象/协议层 | dldw 实现 |
|---|---|---|---|
| PyPI（uv/pip） | ✅ | ✅ | `/pypi/*` 拉穿镜像（自动注入） |
| npm/pnpm/yarn | ✅ | ✅ | `/npm/*` 拉穿镜像（自动注入） |
| apt/yum/dnf | ✅ | ✅ | `/mirror/*` 通用静态镜像（.deb/.rpm 入库，元数据透传防过期） |
| Go modules | ✅ | ✅（GOPROXY 协议） | `/gomod/*`（版本化文件缓存，自动注入 GOPROXY） |
| git | ❌ packfile 按协商生成 | ✅ tarball/对象 | `dldw repo`（codeload tarball 永久缓存）；完整历史走隧道；bare mirror 属进阶 |
| docker | ❌ 认证动态 | ✅ 层按 SHA256 寻址 | `/v2/*` Registry V2 拉穿（blob 入库 + digest 校验，manifest 短 TTL）；需 Docker Hub 账号绕开匿名限流 + daemon.json 配置 |
| Maven/Gradle、cargo、conda | ✅ | ✅ | 复用 `/mirror/*`（专用注入器后续提供） |
| 任意静态大文件 | ✅ | ✅ | `dldw get <URL>`（显式地址，永久缓存） |

## 扩展组件（v1.1–v1.4，超出原方案范围）

- **内嵌代理核心（v1.1）**：`proxy.enabled` + hysteria2 分享链接 → 托管 sing-box 子进程（mixed 入站 127.0.0.1:1080），执行器与隧道出口自动接管，无需宿主机代理客户端；也可用 `executor/tunnel.upstream_proxy` 直连指定既有代理。
- **PyPI 拉穿镜像（v1.1）**：`/pypi/simple/<包>/` 索引代理（HTML 与 PEP 691 JSON 双格式重写 + 内存缓存）与 `/pypi/packages/<路径>`（wheel 302 到预签名；首次抓取入库）。
- **npm 拉穿镜像（v1.2）**：`/npm/<包>` 元数据代理（tarball 链接重写）与 `/npm/tarball/<路径>`（tgz 缓存 302）；publish 等写操作不走镜像。
- **镜像地址自动注入（v1.2）**：包装 uv/pip/npm/pnpm/yarn/go 时探测 `/api/v1/capabilities`，用户未自配源则注入 `UV_INDEX_URL` / `PIP_INDEX_URL` / `NPM_CONFIG_REGISTRY` / `GOPROXY`；优先级：命令行 flag > 环境变量 > 项目/用户配置文件 > 自动注入，用户配置永远优先。
- **通用静态镜像与 Go modules（v1.3）**：`/mirror/{协议}/{域名}/{路径}` 覆盖 apt(.deb)/yum·dnf(.rpm)/任意静态文件（仓库元数据自动识别并透传，防止拿到过期索引；by-hash 路径缓存）；`/gomod/*` 实现 GOPROXY 协议（版本化 .zip/.mod/.info 永久缓存，list/latest/sumdb 透传）。
- **Docker Registry 镜像与 `dldw repo`（v1.4）**：`/v2/*` 拉穿——blob 按 digest 入库并强制 SHA256 校验，tag manifest 短 TTL / digest manifest 永久缓存，服务端统一持有 Docker Hub 凭证；`dldw repo <地址>` 把仓库快照转为 codeload tarball 走缓存并安全解包（路径穿越整体拒绝）。

## 错误码

`E_PROXY_BIND E_PROXY_LOOP E_TOOL_ADAPTER E_RESOLVE_AUTH E_RESOLVE_TIMEOUT E_PRESIGN_EXPIRED E_SSRF_DENIED E_PORT_DENIED E_DIRECT_UNAVAILABLE E_DOCKER_DAEMON E_NOT_CACHEABLE E_TASK_DEAD E_CHECKSUM_MISMATCH E_OUTPUT_EXISTS E_RATE_LIMITED E_REPLAY E_NOT_WHITELISTED`

## 安全模型

- 出口白名单：仅域名、点边界安全匹配；IP 字面量永不匹配。
- SSRF 防护：loopback/私网/链路本地/保留段/CGNAT/TEST-NET/组播在**客户端与服务端双侧阻断**；拨号时校验 IP，缓解 DNS 重绑定。
- 端口默认全链路只允许 80/443（隧道、直连出口、源站抓取）。
- 令牌只存哈希；refresh 轮换；吊销即时生效；隧道 nonce 每 token 单次有效。
- 预签名 URL 短时效（默认 15 分钟）且可刷新（`POST /api/v1/tasks/:id/refresh`）。
- 审计日志携带 `request_id`/`conn_id`；URL 查询值脱敏。

## 仓库结构

```
cmd/dldw/                     命令行入口
internal/client/{wrapper,proxy,downloader,adapters,config,doctor,bench,cli}
internal/server/{api,tunnel,ratelimit,audit,auth,app,proxycore,
                 mirrorcore,pypi,npm,gomod,webmirror,registrymirror}
internal/transfer/{tasks,executor,aria2ctl,storage{,localfs,s3,openliststore},presign,openlist}
internal/policy/{whitelist,ssrf}   客户端/服务端共享
internal/protocol/dldw1            隧道握手协议（共享）
internal/upstreamproxy             HTTP CONNECT 上游代理拨号
deploy/ scripts/                   compose/systemd/示例配置/构建/冒烟测试
```

## 现状与限制（v1.4）

- Docker Registry 镜像已实现，但**冷拉取依赖 Docker Hub 凭证**（匿名 IP 限流是常态）；客户端需在 daemon.json 配置 `registry-mirrors` 并重启 dockerd/Docker Desktop。
- git 完整 clone 不缓存（协议按协商生成 packfile）；快照场景用 `dldw repo`，完整历史走隧道；bare mirror 留作进阶扩展。
- Windows 信号转发依赖共享控制台的 Ctrl+C；不自动转发硬终止信号。
- `apt/dnf/docker` 适配器默认只提示；改动系统需要显式 `--apply`（及 root），且从不重启 dockerd。
- `direct_fallback: ask` 在非交互场景表现为"否"；需要回退时显式传 `--direct-fallback`。
- Maven/cargo/conda 已可通过 `/mirror/*` 手动接入，专用注入器未提供。
- 拉穿镜像端点（`/pypi /npm /mirror /gomod /v2`）默认无鉴权：请只监听 127.0.0.1 或置于可信网络/反向代理之后。
