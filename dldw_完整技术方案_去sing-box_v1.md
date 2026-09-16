# dldw 完整技术方案（去 sing-box 版）

版本：v1.0-scheme  
日期：2026-09-16  
定位：轻量跨平台命令行下载加速与受控代理工具  
范围：客户端 Wrapper、本地 HTTP/CONNECT 代理、`dldw get` 下载加速、服务端受控隧道出口、缓存/对象存储直传；Docker 加速作为独立可选组件。

---

## 1. 项目概述

### 1.1 背景

开发中访问 GitHub Release、PyPI、npm、Docker Hub、Quay/GHCR/GCR 等经常受网络质量、出口限制或远距离传输影响。传统方案需要手动配置代理、镜像站、daemon 配置或下载加速站，体验割裂且不可审计。

dldw 的目标是把常用命令变成可观测、可回退、可加速的一层：

```bash
dldw git clone https://github.com/org/repo.git
dldw pip install -r requirements.txt
dldw curl -O https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw docker pull nginx
dldw get https://github.com/org/repo/releases/download/v1/app.tar.gz
```

### 1.2 设计原则

1. **低依赖**：客户端不使用 sing-box/libbox/gomobile，不实现 VPN/TUN/SOCKS 入站。
2. **显式分流**：本地代理只按 HTTP 代理语义工作；HTTPS 只做 CONNECT，不做 MITM。
3. **大文件不走隧道**：静态大文件通过 `dldw get` 走服务端缓存和对象存储预签名直传。
4. **白名单受控**：默认仅白名单域名走服务端隧道；非白名单直连；私网地址拒绝。
5. **工具兼容优先**：对 curl/wget/git/pip/uv 等优先使用 HTTP(S)_PROXY；对 apt/yum/dnf/docker 等特殊工具提供配置生成或显式应用。
6. **可诊断可回退**：所有关键路径有 request_id/conn_id、错误码、doctor、benchmark 和 direct fallback。

### 1.3 目标

- 支持 Linux/macOS/Windows CLI；移动端不纳入 v1。
- 包装常用命令并注入代理环境：curl、wget、git、pip、uv、conda、npm、apt、yum/dnf、docker 等。
- 提供 `dldw get`：断点续传、分块并发、sha256 校验、缓存命中后对象存储直传。
- 服务端提供受控隧道出口、resolve API、缓存任务、对象存储直传；Docker Registry Mirror 独立可选。

### 1.4 非目标

- 不做 VPN/TUN、透明网卡代理、系统级全局劫持。
- 不做 sing-box/clash/v2ray 规则生态；不承诺 SOCKS5。
- 不解析 HTTPS 内容，不做证书安装与 MITM。
- 不承诺所有工具在所有权限环境下都被代理；root/daemon/桌面图形工具需要显式配置。
- 不把 Docker 自动重启 dockerd 作为默认路径。

---

## 2. 总体架构

```text
用户命令
  dldw <tool> [args...] 或 dldw get <url> [output]
        |
        v
[Client Wrapper]
  解析命令、启动临时本地 HTTP 代理、注入代理环境、执行子进程、清理生命周期
        |
        +--> A. 工具流量：Local Proxy
        |      - 普通 HTTP：直接转发/改写
        |      - HTTPS：CONNECT host:port
        |      - 白名单 host：连接 Server Tunnel，发送 CONNECT host:port token
        |      - 非白名单：direct；私网/保留段拒绝
        |
        +--> B. 下载流量：Downloader fast path
               - POST /api/v1/resolve
               - cached：S3/OSS/MinIO presigned + range 直传
               - downloading/queued：任务轮询/长轮询，ready 后下载
               - 失败：显式 direct fallback 或报错
[Server]
  Control API：resolve、task、refresh、doctor、whitelist、auth
  Tunnel：白名单 CONNECT 出口，DNS+SSRF+限流+审计
  Cache：OpenList 元数据 + Aria2 执行器 + S3/OSS/MinIO 存储
  Registry Mirror：可选独立 Docker V2 pull-through cache
```

架构边界：本地代理解决“可达性”，`dldw get` 解决“大文件吞吐”。二者不要混为一谈。

---

## 3. 客户端设计

## 3.1 CLI 命令面

```bash
dldw <command> [args...]                 # 包装命令
dldw get <url> [output]                  # 下载加速主链路
dldw env [--shell bash|zsh|fish|powershell|cmd]
dldw doctor [--fix]
dldw benchmark [--url URL] [--mode direct|tunnel|presigned]
dldw config init|show|set|unset
dldw proxy --port 8080                   # 可选后置，v1 可不发布
```

选项：
- `--no-proxy`：不启动本地代理，只运行原命令。
- `--force-tunnel`：调试项，仍受 SSRF/端口/私网限制，默认关闭。
- `--direct-fallback` / `--no-direct-fallback`：控制失败时是否回退直连。
- `--profile NAME`、`--token TOKEN`、`--server URL`。
- `-v/-vv`：日志级别；默认 WARN。

## 3.2 Wrapper 流程

1. 解析 `argv`：识别工具名；未知工具仍尝试注入 env 后执行，但标记兼容等级 unknown。
2. 启动 local proxy：bind `127.0.0.1:0`，必须 listen 成功后才读取端口。
3. 注入环境变量：仅 HTTP/HTTPS 代理与 no_proxy；不默认覆盖 all_proxy。
4. 对特殊工具进入 adapter：apt/yum/dnf/docker/conda 等做提示或生成配置片段。
5. `exec` 子进程：透传 stdin/stdout/stderr；Windows 下注意句柄与退出码映射。
6. 信号处理：SIGINT/SIGTERM 先停止接收新连接，排空活跃连接，超时后关闭。
7. 退出：返回子进程 exit code；清理端口、临时文件、连接池。

状态机：

```text
uninitialized -> starting_proxy -> proxy_ready -> adapter_pre -> child_running -> draining -> cleanup -> exited
任何失败：error_report -> cleanup -> exited
```

## 3.3 本地代理

实现要求：
- HTTP/1.1 代理：处理 absolute URI 请求；清理 Proxy-Connection、Via、X-Forwarded-For 等头；限制请求头大小。
- CONNECT：解析 `host:port`；建立到目标或服务端隧道；之后双向拷贝字节。
- 白名单：精确匹配、后缀匹配；必须防 `github.com.evil.com` 误命中。
- 直连：仅对非白名单；连接失败不自动升级到隧道，除非用户显式开启。
- 安全：拒绝 loopback/private/reserved/multicast；默认目标端口 80/443。
- 观测：连接数、字节数、host TopN、tunnel/direct 分布、错误码。

注入环境：

```bash
http_proxy=http://127.0.0.1:PORT
https_proxy=http://127.0.0.1:PORT
HTTP_PROXY=http://127.0.0.1:PORT
HTTPS_PROXY=http://127.0.0.1:PORT
no_proxy=localhost,127.0.0.1,::1,*.local
NO_PROXY=localhost,127.0.0.1,::1,*.local
```

## 3.4 工具适配矩阵

| 工具 | 代理方式 | 支持等级 | 备注 |
|---|---|---|---|
| curl | env: `http_proxy/https_proxy` 或 `-x` | 高 | 支持 HTTP/HTTPS/FTP 中 HTTP 代理语义；FTP 不保证 |
| wget | env 或 `--proxy=on/off` | 高 | 读取 `http_proxy/https_proxy`；配置文件也可 |
| git | env；按 URL 走 HTTP(S) | 高 | `git clone https://...` 走代理；SSH 不走 HTTP 代理，需单独说明 |
| pip | env | 高 | pip 支持 HTTP proxy；index 与 files 域名都要在白名单或直连可达 |
| uv | env | 高 | 与 pip 类似；并发下载更激进，注意本地代理连接数 |
| conda | env `.condarc proxy_servers` | 中 | 仅 env 有时不够，建议生成 `.condarc` 片段或用户已有配置合并 |
| npm | env；也可 `npm config set proxy` | 中高 | 部分场景需 `https-proxy`；建议 adapter 检测并提示 |
| apt | env 对 apt 方法不稳定；推荐生成 apt.conf.d | 中 | 默认只提示；`--apply` 写入 `/etc/apt/apt.conf.d/99dldw` 需 root |
| yum/dnf | env 对插件不稳定；推荐配置 proxy= | 中 | 生成 `/etc/yum.repos.d/*.repo` patch 或 `/etc/dnf/dnf.conf` 片段需 root |
| docker | CLI env 不作用于 dockerd | 低-中 | 仅提示配置 daemon.json registry-mirrors 或 systemd drop-in；不自动重启 |
| BuildKit | 需 build-arg/driver | 低 | 不默认处理；文档说明 `HTTP_PROXY` build-arg |
| go/rust/cargo | env 多数可用 | 中 | 依赖具体版本与 CA/代理实现；提供诊断 |
| conda/mamba | env + condarc | 中 | 同上 |

Adapter 行为：
- `curl/wget/git/pip/uv`：直接注入 env。
- `npm`：检测 `npm config get proxy/https-proxy/registry`，不一致则警告；可选写用户级 npmrc 需确认。
- `apt`：输出建议片段；不默认写系统目录。
- `yum/dnf`：输出 repo proxy 片段；不默认改系统。
- `docker`：检查 daemon.json 是否配置 registry-mirrors；未配置则提示；不重启服务。
- `conda`：合并生成 `~/.condarc` 片段需 `--apply`；避免覆盖已有 proxy_servers。

## 3.5 `dldw get` 下载器

能力：
- resolve：查询缓存；未命中创建任务；幂等。
- 直传：presigned URL 直连 S3/OSS/MinIO/CDN；支持 Range。
- 分块：默认 8-16 MiB；小文件不并发；失败 chunk 单独重试。
- 校验：优先 sha256；无 sha256 时记录 etag/size/last_modified。
- 续传：`.part` 文件 + chunk bitmap；presigned 临期 refresh。
- 回退：resolve 失败/对象存储不可达时，显式 direct 或报错，不默认隧道。

流程：

```text
canonical_url -> cache_key
POST /api/v1/resolve {url, client_id, capabilities:{range, concurrent, sha256}}
if cached: HEAD/GET presigned; parallel ranges; write .part; rename; verify
if queued/downloading: poll task or long-poll; timeout 显式失败
if server_error: direct fallback 可选；默认询问/提示
```

---

## 4. 服务端设计

## 4.1 控制 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /healthz /readyz | 健康检查；readyz 细分依赖 |
| POST | /api/v1/resolve | 查询/创建缓存任务，幂等 |
| GET | /api/v1/tasks/:id | 任务进度与状态 |
| POST | /api/v1/tasks/:id/refresh | 刷新 presigned URL |
| GET | /api/v1/whitelist | 下发白名单与版本 |
| POST | /api/v1/introspect | 服务端视角诊断 token/DNS/时间/出口 |
| POST | /api/v1/token | 设备注册/刷新/吊销 |
| GET | /v2/ | Docker Registry Mirror，可选独立 |

resolve 响应建议字段：`request_id,status,cache_key,artifact{size,sha256,etag,content_type},download{mode,urls,expires_at,supports_range},task{id,progress}`。

## 4.2 隧道出口

协议：

```text
client -> server: DLDW/1 CONNECT <host> <port> <token> <nonce> <client_id> <flags>

server -> client: DLDW/1 OK <conn_id> <expires_in> <resolved_ip>

server -> client: DLDW/1 ERR <code> <message>

之后裸 TCP 双向转发。
```

服务端在 OK 前完成：token 校验、nonce 重放、白名单、DNS 解析、私网/保留段阻断、端口策略、限流。默认仅 80/443；`allow_large=false`。支持 TLS、空闲超时、半关闭、conn_id 审计。

## 4.3 缓存与上传

组件：OpenList 管理文件索引/元数据；Aria2 作为下载执行器；S3/MinIO/OSS 存对象；PostgreSQL/SQLite 存任务与设备。

状态机：

```text
queued -> downloading -> downloaded -> uploading -> registering -> ready
                         \-> failed(retryable) -> dead
```

一致性要求：
- resolve 幂等：同一 cache_key 并发 singleflight。
- Aria2 崩溃：任务可从持久化状态恢复；对象已上传但元数据缺失可自愈。
- 去重：cache_key = sha256(canonical_url + artifact_family_hint)。仅缓存可识别静态资源：github-release、pypi-file、npm-tarball、docker-blob、generic-static。
- GC：临时文件 orphan 清理；缓存 TTL/LRU；任务创建限流。

## 4.4 Docker Registry Mirror（独立可选）

兼容 Registry V2：支持匿名公共镜像 pull-through cache；实现 manifest/blob 的 HEAD/GET、digest 校验、range、上游错误透传。私有 registry、云厂商登录态、跨平台 manifest 选择不进 v1 核心。服务端可用性要高，因为 docker 客户端回退体验差。

---

## 5. 安全设计

- SSRF：域名白名单 + DNS 后 IP 校验；阻断 loopback/private/link-local/reserved/multicast；防 DNS rebinding。
- 端口：默认 80/443；其他端口需配置。
- 鉴权：device token 与控制 API 密钥分离；支持吊销；nonce 防重放。
- 限流：按 IP/device/token/host/任务创建/隧道并发/隧道字节数。
- TLS：控制 API 与隧道默认 TLS；对象存储 presigned 短时效并支持 refresh。
- 日志：request_id/conn_id/cache_key/状态码/字节数/耗时；URL query 脱敏；默认不记录正文。
- 输入校验：URL 长度、host、port、token、nonce 严格校验；错误码不泄露内网拓扑。

---

## 6. 配置模型

优先级：`runtime flags > tool adapter overrides > profile > defaults`。

```yaml
server: https://dldw.example.com
token_file: ~/.dldw/token
proxy:
  bind: 127.0.0.1
  port: 0
  mode: whitelist_only
  fallback: direct
  allow_large_over_tunnel: false
download:
  chunk_size: 16MiB
  concurrency: 8
  refresh_before: 120s
  direct_fallback: ask
whitelist_version: 2026-09-16.1
security:
  block_private: true
  ports: [80, 443]
```

支持 shell 输出：`eval $(dldw env)` 或 PowerShell `dldw env --shell powershell | Invoke-Expression`。

---

## 7. 错误码与诊断

客户端错误码建议：
- `E_PROXY_BIND`：端口绑定失败。
- `E_PROXY_LOOP`：检测到代理回环。
- `E_TOOL_ADAPTER`：特殊工具配置未应用。
- `E_RESOLVE_AUTH`：token 失效。
- `E_RESOLSE_TIMEOUT`：resolve 超时，注意拼写统一为 E_RESOLVE_TIMEOUT。
- `E_PRESIGN_EXPIRED`：可 refresh 重试。
- `E_SSRF_DENIED`：私网或端口被拒绝。
- `E_DIRECT_UNAVAILABLE`：直连失败且无 fallback。
- `E_DOCKER_DAEMON`：dockerd 未配置或需手动配置。

`dldw doctor` 检查：端口、时间偏移、DNS、服务端 health/ready、token、白名单版本、对象存储探测、工具适配状态、残留进程。`dldw benchmark` 输出 direct/tunnel/presigned 吞吐、首字节、失败率。

---

## 8. 性能与容量

指标：get p50/p95 启动耗时；presigned 命中率；服务端零中转字节占比；隧道 p99 首字节；Aria2 成功率；resolve 单飞命中率；代理活跃连接/FD/goroutine；Docker blob 加速比。

优化：本地代理 upstream 复用；CONNECT buffer 32-64KiB；TCP_NODELAY；隧道不做大文件；分块失败局部重试；控制面与数据面分离；热点 Release 单飞；对象存储 multipart；慢连接 TopN 与熔断。

---

## 9. 测试策略

- 单元：URL canonicalize、白名单匹配、SSRF、握手编解码、任务状态机、续传 bitmap。
- 集成：get 命中/未命中/过期 refresh；git clone；pip install 大包；curl release；并发 resolve 单飞；隧道私网拒绝；Ctrl-C 清理；Aria2 崩溃恢复。
- 兼容矩阵：Linux/macOS/Windows；bash/zsh/fish/PowerShell；sudo/apt/dnf/rootless docker。
- 混沌：S3 5xx、Aria2 kill、OpenList 重启、presigned 403、隧道半开、DNS rebinding、慢速对象存储。
- 安全：SSRF fuzz、白名单绕过 fuzz、重放、限流、吊销、日志脱敏。

---

## 10. 项目结构

```text
dldw/
  cmd/dldw/
  internal/client/{wrapper,proxy,downloader,adapters,config,doctor,bench,protocol}
  internal/server/{api,tunnel,ratelimit,audit,auth,policy}
  internal/transfer/{resolve,tasks,aria2ctl,storage,openlist,presign}
  internal/registrymirror/        # optional
  deploy/compose/ systemd/ docker-registry/
  docs/ scripts/
```

`policy/ssrf` 与 `protocol` 应在 client/server 共享，保证白名单与私网判定一致。

---

## 11. 里程碑

阶段 0，1 周：CLI/doctor/env、health/ready/resolve mock、request_id/conn_id、CI。  
阶段 1，2-3 周：`dldw get` 闭环，幂等 resolve、Aria2/S3/OpenList、presigned/range/sha256/refresh、benchmark。  
阶段 2，2-3 周：纯 Go HTTP/CONNECT 代理、白名单 tunnel/direct、curl/wget/git/pip/uv、npm/conda/apt/yum adapter 提示、Windows/macOS/Linux 构建。  
阶段 3，2 周：隧道硬化、SSRF、限流、吊销、审计、TLS、混沌与兼容矩阵。  
阶段 4，可选：Docker Registry Mirror、常驻 proxy、更多工具、安卓/iOS 独立评估。

---

## 12. 风险与应对

| 风险 | 应对 |
|---|---|
| 用户期望包装 curl 自动缓存大文件 | 文档明确边界；大文件引导 `dldw get` |
| apt/yum/docker 需要 root 或 daemon 配置 | 默认只提示；`--apply` 显式；不自动重启服务 |
| 工具不读 env 或只读 SOCKS | doctor 检测；adapter 配置；不支持则明确失败 |
| HTTPS 看不到 URL | 不做 MITM；按域名分流；get 显式 URL |
| 隧道承载大文件 | 默认禁止；阈值；监控与限流 |
| presigned 不可达 | probe + direct fallback；统计零中转占比 |
| Aria2/OpenList 不一致 | 状态机、持久化、单飞、自愈、GC |
| SSRF/DNS rebinding | 双侧校验、短 TTL、连接前重解析 |
| Docker Mirror 回退差 | 独立 SLA；上游错误透传；不吞 404/401/429/5xx |

---

## 13. 示例

```bash
# 包装工具
dldw git clone https://github.com/org/repo.git
dldw curl -L -O https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw wget https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw pip install -r requirements.txt
dldw uv pip install -r requirements.txt
dldw npm install
dldw apt update                 # 默认提示；root 且 --apply 才写 apt.conf.d
dldw dnf install pkg            # 默认提示；不自动改 repo
dldw docker pull nginx          # 仅检查 daemon.json 并提示，不重启 dockerd

# 大文件下载主链路
dldw get https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw get --concurrency 16 --chunk 32MiB URL

# 诊断与环境
dldw doctor --fix
dldw benchmark --mode presigned --url URL
eval $(dldw env)
```

最终定位：dldw v1 是**低依赖、可审计、可回退的命令行下载加速层**：包装命令解决白名单可达，`dldw get` 解决大文件吞吐，服务端负责受控出口、缓存与对象存储直传。
