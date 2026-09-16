# dldw

低依赖、可审计、可回退的命令行下载加速与受控代理层（[技术方案](dldw_完整技术方案_去sing-box_v1.md)）。

A lightweight, auditable, fallback-friendly CLI download accelerator and controlled proxy layer.

- **Wrapping commands solves reachability**: `dldw git clone ...`, `dldw pip install ...` run through a temporary local HTTP proxy; whitelisted hosts egress via the server tunnel, everything else goes direct, private/reserved targets are refused.
- **`dldw get` solves throughput**: large static artifacts are fetched through the server cache and delivered from object storage via presigned URLs with ranged parallel transfer — the server relays zero bytes for cache hits.
- **Pull-through mirrors solve package ecosystems**: PyPI/npm/Go modules/apt/yum/Docker-Registry each get a protocol-aware cache (see 能力矩阵 below), auto-injected by the wrapper when the user hasn't configured their own index.
- **The server is a controlled egress**: token auth, nonce replay protection, domain whitelist, SSRF/DNS-rebinding guards, port policy, rate limits, JSON-line audit logs, and an optional embedded sing-box proxy core (bring your own hysteria2 share link — the server becomes fully self-contained).

No TUN / SOCKS / MITM. HTTPS is CONNECT-only. Pure Go, zero third-party dependencies (sing-box is an orchestrated child process, not a linked library).

---

## Build

```bash
# any of: Windows / Linux / macOS
go build ./cmd/dldw
# all platforms + version stamps
scripts/build.sh          # or scripts\build.ps1
# unit + integration tests
go test ./...
# end-to-end smoke test (server + origin + get + doctor)
scripts/smoke.ps1
```

## Server quickstart

```bash
# 1. copy the ANNOTATED config template and edit it (every field documented)
cp deploy/server.example.yaml /etc/dldw/server.yaml
vi /etc/dldw/server.yaml
# 2. whitelist (also annotated; hot-reloads on save)
cp deploy/whitelist.example.txt /etc/dldw/whitelist.txt
# 3. run
dldw serve --config /etc/dldw/server.yaml
# endpoints:
#   http://127.0.0.1:8080  control API
#   http://127.0.0.1:8081  DLDW/1 tunnel (enable TLS for production)
```

Also available: `deploy/compose/docker-compose.yml`, `deploy/systemd/dldw.service`, root `Dockerfile`.

Storage drivers: `localfs`（默认；HMAC 预签名，`/files/` 提供 Range 下载）、`s3`（SigV4 预签名直传——AWS S3 / 阿里云 OSS / 腾讯 COS / Cloudflare R2 等一切 S3 兼容后端，缓存命中流量零中转）、别名 `minio`（= s3 + path-style）与 `openlist`（把 OpenList/AList 挂载当作存储：S3 类挂载返回底层直链，本地/WebDAV 类挂载走 OpenList `/d/` 中转，Range 透传）。Executors: `builtin` (default) and `aria2` (JSON-RPC).

> 接入新存储后端：实现 `internal/transfer/storage.Storage` 接口（`PresignGet/PresignHead/Put/Head/Get/Delete/Ping`）并在 `app.New` 的 switch 注册。注意 `PresignGet` 返回的 URL 决定了流量路径——直链=零中转，代理 URL=中转。

The whitelist file (`whitelist_file`) hot-reloads on change. Token registration can be disabled with `auth.allow_registration=false` after onboarding your devices.

## Client quickstart

```bash
dldw config init                 # 写出带注释的 ~/.dldw/config.yaml，按需编辑
dldw config set server https://dldw.example.com
dldw doctor --fix                 # registers a device token

dldw git clone https://github.com/org/repo.git
dldw curl -L -O https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw pip install -r requirements.txt
dldw uv pip install -r requirements.txt
dldw npm install                  # adapter warns on npm config conflicts
dldw apt update                   # prints the apt.conf.d snippet (root + --apply writes it)
dldw docker pull nginx            # checks daemon.json, prints guidance only

dldw get https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw get --concurrency 16 --chunk 32MiB URL out.tar.gz

dldw repo https://github.com/org/repo            # 仓库快照（tarball 永久缓存）
dldw repo https://github.com/org/repo/tree/dev d2

dldw benchmark --url URL --mode all
eval "$(dldw env)"                # or: dldw env --shell powershell | Invoke-Expression
```

配置文件全部有**带注释模板**，直接照着改即可：

- 客户端：`dldw config init` 生成带完整注释的 `~/.dldw/config.yaml`（每个选项都有说明与默认值）。`dldw config set` 写入的是 `~/.dldw/config.json`（机器格式），一旦存在优先于 yaml 生效——两者留一个即可。
- 服务端：`deploy/server.example.yaml`（每个字段含默认值、生产注意事项与端口约定）。JSON 格式同样支持（字段同名），但无法写注释。
- 白名单：`deploy/whitelist.example.txt`（格式/匹配规则/热加载说明）。

优先级 `flags > adapters > config > defaults`。客户端关键选项：

```yaml
server: https://dldw.example.com
proxy:  { bind: 127.0.0.1, port: 0 }        # port 0 = ephemeral per invocation
download:
  chunk_size: 16MiB
  concurrency: 8
  refresh_before: 120s
  direct_fallback: ask                      # ask | always | never
security:
  block_private: true
  ports: [80, 443]
```

> 端口约定（改端口前必读）：客户端从 `server` URL 推导隧道地址——URL 带显式端口 `P` 时隧道端口为 `P+1`；`https://` 默认 4443，`http://` 默认 8081。修改服务端 `tunnel.listen` 时必须同步此约定。

## Command surface

| Command | Purpose |
|---|---|
| `dldw <tool> [args...]` | wrap a tool: local proxy + env injection + adapters + mirror auto-injection |
| `dldw get <url> [out]` | resolve → presigned ranged download, resume, sha256 verify |
| `dldw repo <git-url> [dir]` | repo snapshot via codeload tarball (cached), anti path-traversal extract |
| `dldw env` | shell exports for a persistent proxy (`dldw proxy --port N`) |
| `dldw doctor [--fix]` | diagnostics: bind, DNS, skew, health/ready, token, whitelist, storage, tools |
| `dldw benchmark` | direct / tunnel / presigned TTFB + throughput |
| `dldw config` | init / show / set / unset / path |
| `dldw proxy` | long-running local proxy with periodic whitelist refresh |
| `dldw serve [--no-proxy-core]` | run the server (flag disables the embedded proxy core) |

Global flags (before the command): `--server --token --profile --no-proxy --apply --direct-fallback/--no-direct-fallback --force-tunnel -v/-vv`.

## Architecture

```
dldw <tool> ──> local HTTP/CONNECT proxy ──┬─ whitelisted host ──> DLDW/1 tunnel ──> server egress (SSRF/limits/audit)
                                           └─ everything else  ──> direct (private targets refused)
dldw get   ──> POST /api/v1/resolve ──> cached: presigned URL ──> ranged parallel GET (client ↔ object storage)
                                  └─ miss: task (queued→…→ready) ──> refresh ──> presigned GET
```

Protocol: `DLDW/1 CONNECT <host> <port> <token> <nonce> <client_id> <flags>` → `DLDW/1 OK <conn_id> <expires_in> <resolved_ip>` / `DLDW/1 ERR <code> <msg>`, then raw TCP.

## Error codes

`E_PROXY_BIND E_PROXY_LOOP E_TOOL_ADAPTER E_RESOLVE_AUTH E_RESOLVE_TIMEOUT E_PRESIGN_EXPIRED E_SSRF_DENIED E_PORT_DENIED E_DIRECT_UNAVAILABLE E_DOCKER_DAEMON E_NOT_CACHEABLE E_TASK_DEAD E_CHECKSUM_MISMATCH E_OUTPUT_EXISTS E_RATE_LIMITED E_REPLAY E_NOT_WHITELISTED` — see spec §7.

## Security model (summary)

- Egress allowlist: domains only, dot-boundary safe matching; IP literals never match.
- SSRF: loopback/private/link-local/reserved/CGNAT/TEST-NET/multicast blocked on **both** client and server; dial-time validation mitigates DNS rebinding.
- Ports default to 80/443 everywhere (tunnel, direct egress, origin fetch).
- Tokens are stored hashed; refresh rotates; revocation is immediate; tunnel nonces are single-use per token.
- Presigned URLs are short-lived (default 15m) and refreshable (`POST /api/v1/tasks/:id/refresh`).
- Audit logs carry `request_id`/`conn_id`; URL query values are redacted.

## Repository layout

```
cmd/dldw/                     CLI entry
internal/client/{wrapper,proxy,downloader,adapters,config,doctor,bench,cli}
internal/server/{api,tunnel,ratelimit,audit,auth,app,proxycore,
                 mirrorcore,pypi,npm,gomod,webmirror,registrymirror}
internal/transfer/{tasks,executor,aria2ctl,storage{,localfs,s3,openliststore},presign,openlist}
internal/policy/{whitelist,ssrf}   shared client/server
internal/protocol/dldw1            tunnel handshake (shared)
internal/upstreamproxy             HTTP CONNECT 上游代理拨号
deploy/ scripts/                   compose/systemd/examples/build/smoke
```

## 扩展组件（v1.1–v1.4，超出原方案范围）

- **内嵌代理核心（v1.1）**：`proxy.enabled` + hysteria2 分享链接 -> dldw 托管 sing-box 子进程（mixed 入站 127.0.0.1:1080），executor/隧道出口自动接管，无需宿主机代理客户端；`dldw serve --no-proxy-core` 可在启动时禁用。上游代理也可直连指定（`executor/tunnel.upstream_proxy`）。
- **PyPI 拉穿镜像（v1.1）**：`/pypi/simple/<pkg>/` 索引代理（HTML/PEP691 JSON 双格式重写+内存缓存）与 `/pypi/packages/<path>`（wheel 302 预签名；首次抓取入库）。
- **npm 拉穿镜像（v1.2）**：`/npm/<pkg>` 元数据代理（tarball 链接重写）与 `/npm/tarball/<path>`（tgz 缓存 302）；publish 等写操作不走镜像。
- **镜像地址自动注入（v1.2）**：`dldw uv/pip/npm/pnpm/yarn/go ...` 时 wrapper 探测 `/api/v1/capabilities`，用户未自配 index/registry（优先级：CLI flag > 环境变量 > pyproject/pip.ini/.npmrc/go env > 自动注入）则注入 `UV_INDEX_URL` / `PIP_INDEX_URL` / `NPM_CONFIG_REGISTRY` / `GOPROXY`；用户配置永远优先。
- **通用静态拉穿镜像 + Go modules（v1.3）**：`/mirror/{scheme}/{host}/{path}` 覆盖 apt(.deb)/yum·dnf(.rpm)/任意静态文件（仓库元数据自动识别并透传，防止拿到过期索引）；`/gomod/*` 实现 GOPROXY 协议（版本化 .zip/.mod/.info 永久缓存，list/latest/sumdb 透传）。
- **Docker Registry V2 镜像 + `dldw repo`（v1.4）**：`/v2/*` 拉穿（blob 按 digest 入库并强制 SHA256 校验，tag manifest 短 TTL / digest manifest 永久缓存；服务端统一持有 Docker Hub 凭证绕开匿名限流；客户端 daemon.json 配 `registry-mirrors`）。`dldw repo <url>` 把 git 仓库快照转为 codeload tarball 走缓存并安全解包。

## 缓存能力矩阵（按层区分）

HTTP 层不可缓存 ≠ 不可缓存：git 的 packfile 按协商生成、Docker 的认证令牌是动态的，
但 git 的对象（tarball）、Docker 的层（digest 内容寻址）都是不可变内容——下沉一层即可缓存。

| 工具 | HTTP 层 | 对象/协议层 | dldw 实现 |
|---|---|---|---|
| PyPI (uv/pip) | ✅ | ✅ | `/pypi/*` 拉穿镜像（自动注入） |
| npm/pnpm/yarn | ✅ | ✅ | `/npm/*` 拉穿镜像（自动注入） |
| apt/yum/dnf | ✅ | ✅ | `/mirror/*` 通用静态镜像（.deb/.rpm 入库，元数据透传防过期） |
| Go modules | ✅ | ✅（GOPROXY 协议） | `/gomod/*`（版本化文件缓存，自动注入 GOPROXY） |
| **git** | ❌ packfile 按协商生成 | ✅ tarball/对象 | `dldw repo <url>` 快照命令（codeload tarball 永久缓存）；完整历史走隧道；bare mirror 属进阶 |
| **docker** | ❌ 认证动态 | ✅ 层按 SHA256 寻址 | `/v2/*` Registry V2 拉穿镜像（blob 入库+digest 校验，manifest 短 TTL）；需 Docker Hub 账号绕开匿名限流 + daemon.json registry-mirrors |
| Maven/Gradle、cargo、conda | ✅ | ✅ | 复用 `/mirror/*` 即可（后续提供专用注入） |
| 任意静态大文件 | ✅ | ✅ | `dldw get <url>`（显式 URL，永久缓存） |

## Status / limitations (v1.4)

- Docker Registry 镜像已实现，但**冷拉取依赖 Docker Hub 凭证**（匿名 IP 限流是常态）；客户端需在 daemon.json 配 `registry-mirrors` 并重启 dockerd/Docker Desktop。
- git 完整 clone 不缓存（协议按协商生成 packfile）；快照场景用 `dldw repo`，完整历史走隧道；bare mirror 属进阶扩展（未实现）。
- Windows signal forwarding relies on shared-console Ctrl+C; hard kills are not forwarded automatically.
- `apt/dnf/docker` adapters are hint-first; system changes require explicit `--apply` (and root), and dockerd is never restarted.
- `direct_fallback: ask` currently behaves as "no" in non-interactive contexts; pass `--direct-fallback` to opt in.
- Maven/cargo/conda 已可通过 `/mirror/*` 手动接入，专用注入器未提供。
- 拉穿镜像端点（`/pypi /npm /mirror /gomod /v2`）默认无鉴权：请只监听 127.0.0.1 或置于可信网络/反代之后。
