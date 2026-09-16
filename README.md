# dldw

低依赖、可审计、可回退的命令行下载加速与受控代理层（[技术方案](dldw_完整技术方案_去sing-box_v1.md)）。

A lightweight, auditable, fallback-friendly CLI download accelerator and controlled proxy layer.

- **Wrapping commands solves reachability**: `dldw git clone ...`, `dldw pip install ...` run through a temporary local HTTP proxy; whitelisted hosts egress via the server tunnel, everything else goes direct, private/reserved targets are refused.
- **`dldw get` solves throughput**: large static artifacts are fetched through the server cache (aria2/builtin executor) and delivered from object storage via presigned URLs with ranged parallel transfer — the server relays zero bytes for cache hits.
- **The server is a controlled egress**: token auth, nonce replay protection, domain whitelist, SSRF/DNS-rebinding guards, port policy, rate limits and JSON-line audit logs.

No sing-box / libbox / TUN / SOCKS / MITM. HTTPS is CONNECT-only. Pure Go, zero third-party dependencies.

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

Storage drivers: `localfs` (default; HMAC presigned URLs served under `/files/`) and `s3` (S3/MinIO/OSS via SigV4 presign — large transfers go **direct** client↔object-storage, never through the server). Executors: `builtin` (default) and `aria2` (JSON-RPC).

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
| `dldw <tool> [args...]` | wrap a tool: local proxy + env injection + adapters |
| `dldw get <url> [out]` | resolve → presigned ranged download, resume, sha256 verify |
| `dldw env` | shell exports for a persistent proxy (`dldw proxy --port N`) |
| `dldw doctor [--fix]` | diagnostics: bind, DNS, skew, health/ready, token, whitelist, storage, tools |
| `dldw benchmark` | direct / tunnel / presigned TTFB + throughput |
| `dldw config` | init / show / set / unset / path |
| `dldw proxy` | long-running local proxy with periodic whitelist refresh |
| `dldw serve` | run the server |

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
internal/server/{api,tunnel,ratelimit,audit,auth,app}
internal/transfer/{resolve→tasks,executor,aria2ctl,storage,presign,openlist}
internal/policy/{whitelist,ssrf}   shared client/server
internal/protocol/dldw1            tunnel handshake (shared)
deploy/ scripts/                   compose/systemd/examples/build/smoke
```

## Status / limitations (v1)

- Docker Registry Mirror (pull-through cache) is intentionally **not** in v1 core (spec §4.4, stage 4).
- Windows signal forwarding relies on shared-console Ctrl+C; hard kills are not forwarded automatically.
- `apt/dnf/docker` adapters are hint-first; system changes require explicit `--apply` (and root), and dockerd is never restarted.
- `direct_fallback: ask` currently behaves as "no" in non-interactive contexts; pass `--direct-fallback` to opt in.
- OpenList is wired as an optional metadata client only; the task engine does not require it.
