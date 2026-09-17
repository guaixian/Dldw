# dldw

A lightweight, auditable, fallback-friendly CLI download accelerator and controlled proxy layer.

**[中文文档](README.md)** · [Full technical design (Chinese)](dldw_完整技术方案_去sing-box_v1.md)

## Overview

- **Wrapping commands solves reachability**: `dldw git clone ...`, `dldw pip install ...` run through a temporary local proxy; whitelisted hosts egress via the server tunnel, everything else goes direct, private/reserved targets are refused.
- **`dldw get` solves throughput**: static artifacts are fetched through the server cache and delivered from object storage via presigned URLs with ranged parallel transfer — the server relays zero bytes on cache hits.
- **Pull-through mirrors solve package ecosystems**: PyPI / npm / Go modules / apt·yum / Docker Registry each get a protocol-aware cache (see the capability matrix below), auto-injected by the wrapper when the user has no index configured.
- **The server is a controlled egress**: token auth, nonce replay protection, domain whitelist, SSRF/DNS-rebinding guards, port policy, rate limits, JSON-line audit logs, plus an optional embedded proxy core (bring a hysteria2 share link and the server is fully self-contained).

No TUN / SOCKS / MITM; HTTPS is CONNECT-only. Pure Go, zero third-party dependencies (sing-box runs as an orchestrated child process, not a linked library).

## Build

```bash
# any of: Windows / Linux / macOS
go build ./cmd/dldw
# all platforms + version stamps
scripts/build.sh          # on Windows: scripts\build.ps1
# unit + integration tests
go test ./...
# binary-level end-to-end smoke test (server + origin + get + doctor)
scripts/smoke.ps1
```

## Server quickstart

```bash
# 1. copy the fully annotated config template and edit it
cp deploy/server.example.yaml /etc/dldw/server.yaml
vi /etc/dldw/server.yaml
# 2. whitelist (annotated as well; hot-reloads on save)
cp deploy/whitelist.example.txt /etc/dldw/whitelist.txt
# 3. run
dldw serve --config /etc/dldw/server.yaml
# endpoints:
#   http://127.0.0.1:8080  control API
#   http://127.0.0.1:8081  DLDW/1 tunnel (enable TLS in production)
```

Also available: `deploy/compose/docker-compose.yml`, `deploy/systemd/dldw.service`, root `Dockerfile`.

### Storage drivers

| Driver | Notes |
|---|---|
| `localfs` (default, alias `fs`) | Local filesystem + HMAC presigning, range downloads served from `/files/` |
| `s3` | SigV4 presigned direct transfer — AWS S3, Aliyun OSS, Tencent COS, Cloudflare R2, any S3-compatible backend; zero relayed bytes on cache hits |
| `minio` | Same as s3 with path-style forced (MinIO addressing) |
| `openlist` | Use an OpenList/AList mount as storage: S3-type mounts return underlying direct links; local/WebDAV mounts relay through OpenList `/d/` (range passthrough) |

Executors: `builtin` (default, pure Go with retries) and `aria2` (JSON-RPC).

> Adding a backend: implement `internal/transfer/storage.Storage` (`PresignGet/PresignHead/Put/Head/Get/Delete/Ping`) and register it in the `app.New` switch. The URL returned by `PresignGet` determines the traffic path — a direct link means zero relay, a proxy URL means relayed.

## Client quickstart

```bash
dldw config init                 # writes the annotated ~/.dldw/config.yaml
dldw config set server https://dldw.example.com
dldw doctor --fix                # registers a device token

dldw git clone https://github.com/org/repo.git
dldw curl -L -O https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw pip install -r requirements.txt
dldw uv sync                     # local PyPI mirror auto-injected
dldw npm install                 # local npm mirror auto-injected
dldw apt update                  # prints a hint by default; root + --apply writes apt.conf.d
dldw docker pull nginx           # checks daemon.json, prints guidance only

dldw get https://github.com/org/repo/releases/download/v1/app.tar.gz
dldw get --concurrency 16 --chunk 32MiB URL out.tar.gz

dldw repo https://github.com/org/repo            # repo snapshot (tarball cached forever)
dldw repo https://github.com/org/repo/tree/dev d2

dldw benchmark --url URL --mode all
eval "$(dldw env)"               # PowerShell: dldw env --shell powershell | Invoke-Expression
```

### Configuration

Fully **annotated templates** for everything:

- Client: `dldw config init` generates `~/.dldw/config.yaml`; `dldw config set` writes `~/.dldw/config.json` (which takes precedence once it exists) — keep one of them.
- Server: `deploy/server.example.yaml` (every field documented with defaults, production notes and the port convention).
- Whitelist: `deploy/whitelist.example.txt` (format, matching rules, hot reload).

Precedence: `CLI flags > tool adapters > config file > defaults`.

> **Port convention (read before changing ports)**: the client derives the tunnel address from the `server` URL — an explicit port `P` maps to tunnel port `P+1`; `https://` defaults to 4443, `http://` to 8081. Changing `tunnel.listen` must follow this convention.

## Command surface

| Command | Purpose |
|---|---|
| `dldw <tool> [args...]` | wrap a tool: local proxy + env injection + adapters + mirror auto-injection |
| `dldw get <url> [out]` | resolve → presigned ranged download, resume, sha256 verify |
| `dldw repo <git-url> [dir]` | repo snapshot via codeload tarball (cached) with safe extraction |
| `dldw relay <tool> [args...]` | relay mode: force all traffic through the server tunnel (same as dldc) |
| `dldw env` | shell exports for a persistent proxy (`dldw proxy`) |
| `dldw doctor [--fix]` | diagnostics: bind, DNS, clock skew, health, token, whitelist, storage, tools |
| `dldw benchmark` | direct / tunnel / presigned TTFB and throughput comparison |
| `dldw config` | init / show / set / unset / path |
| `dldw proxy` | long-running local proxy with periodic whitelist refresh |
| `dldw serve [--no-proxy-core]` | run the server (flag disables the embedded proxy core) |

### dldc: the relay client

`dldc` is **the same binary** as `dldw` (copy `dldw.exe` to `dldc.exe`, or use `dldw relay`),
switching to a "relay everything through the server tunnel" mode — covering the cases that
cannot be cached (full `git clone`, arbitrary non-whitelisted sites):

```bash
dldc git clone https://github.com/org/repo.git    # full git protocol via the VPS
dldc curl https://any-site.example/api            # any public host
dldc pip install xxx                              # mirrors hit the cache first, relay for the rest
```

Requires `tunnel.mode: relay_all` on the server (non-whitelisted hosts allowed;
SSRF/port/token/limit policies **all still apply**). The trade-off:
**dldw = precise whitelist tunneling with cache priority; dldc = global relaying**.

Global flags (before the subcommand): `--server --token --profile --no-proxy --apply --direct-fallback/--no-direct-fallback --force-tunnel -v/-vv`.

## Architecture

```
dldw <tool> ──> local HTTP/CONNECT proxy ──┬─ whitelisted host ──> DLDW/1 tunnel ──> server egress (SSRF/limits/audit)
                                           └─ everything else  ──> direct (private targets refused)
dldw get   ──> POST /api/v1/resolve ──> hit: presigned URL ──> ranged parallel GET (client ↔ object storage)
                                  └─ miss: task (queued→…→ready) ──> refresh ──> presigned GET
```

Tunnel protocol: `DLDW/1 CONNECT <host> <port> <token> <nonce> <client_id> <flags>` → `DLDW/1 OK <conn_id> <expires_in> <resolved_ip>` / `DLDW/1 ERR <code> <msg>`, then raw bidirectional TCP.

## Caching capability matrix (by layer)

"Not cacheable at the HTTP layer" does not mean "not cacheable": git packfiles are negotiated
per request and Docker auth tokens are dynamic, but git objects (tarballs) and Docker layers
(digest content-addressed) are immutable — drop one layer down and they cache perfectly.

| Tool | HTTP layer | Object/protocol layer | dldw implementation |
|---|---|---|---|
| PyPI (uv/pip) | ✅ | ✅ | `/pypi/*` pull-through mirror (auto-injected) |
| npm/pnpm/yarn | ✅ | ✅ | `/npm/*` pull-through mirror (auto-injected) |
| apt/yum/dnf | ✅ | ✅ | `/mirror/*` generic static mirror (.deb/.rpm stored; repo metadata passed through to avoid stale indexes) |
| Go modules | ✅ | ✅ (GOPROXY protocol) | `/gomod/*` (immutable versioned files cached; GOPROXY auto-injected) |
| git | ❌ packfiles negotiated | ✅ tarball/objects | `dldw repo` (codeload tarball cached forever); full history goes through the tunnel; bare mirror is an advanced extension |
| docker | ❌ auth is dynamic | ✅ layers SHA256-addressed | `/v2/*` Registry V2 pull-through (blobs stored with forced digest check, manifests short-TTL); needs a Docker Hub account to dodge anonymous rate limits + daemon.json |
| Maven/Gradle, cargo, conda | ✅ | ✅ | reuse `/mirror/*` (dedicated injectors to come) |
| any static file | ✅ | ✅ | `dldw get <url>` (explicit URL, cached forever) |

## Extensions (v1.1–v1.4, beyond the original design)

- **Embedded proxy core (v1.1)**: `proxy.enabled` + a hysteria2 share link → dldw orchestrates a sing-box child process (mixed inbound on 127.0.0.1:1080); executor and tunnel egress adopt it automatically — no host-side proxy client needed. Alternatively point `executor/tunnel.upstream_proxy` at any existing proxy.
- **PyPI pull-through mirror (v1.1)**: `/pypi/simple/<pkg>/` index proxy (HTML and PEP 691 JSON rewritten + in-memory cache) and `/pypi/packages/<path>` (wheel 302 to a presigned URL; first hit fetches and stores).
- **npm pull-through mirror (v1.2)**: `/npm/<pkg>` metadata proxy (tarball links rewritten) and `/npm/tarball/<path>` (tgz cached, 302); write operations like publish bypass the mirror.
- **Mirror auto-injection (v1.2)**: when wrapping uv/pip/npm/pnpm/yarn/go the wrapper probes `/api/v1/capabilities` and injects `UV_INDEX_URL` / `PIP_INDEX_URL` / `NPM_CONFIG_REGISTRY` / `GOPROXY` unless the user configured their own — precedence: CLI flags > env vars > project/user config files > auto-injection. User config always wins.
- **Generic static mirror and Go modules (v1.3)**: `/mirror/{scheme}/{host}/{path}` covers apt (.deb), yum/dnf (.rpm) and any static file (repo metadata is detected and passed through so indexes never go stale; by-hash paths cached). `/gomod/*` implements the GOPROXY protocol (immutable versioned .zip/.mod/.info cached; list/latest/sumdb passed through).
- **Docker Registry mirror and `dldw repo` (v1.4)**: `/v2/*` pull-through — blobs stored with a forced SHA256 digest check, tag manifests short-TTL / digest manifests cached forever, Docker Hub credentials held server-side. `dldw repo <url>` turns a repo snapshot into a codeload tarball through the cache and extracts it safely (path traversal fails closed).
- **dldc relay mode and multi-origin failover (v1.5)**: `tunnel.mode: relay_all` plus `dldc` / `dldw relay` (the same binary detects its program name) — pure relaying for any public host, covering the non-cacheable cases (full `git clone` etc.); SSRF/port/token/limit policies are unchanged. The pypi/npm/gomod mirrors accept `*_origins` lists with sequential failover (à la verdaccio uplinks): when the primary origin fails or rate-limits, the next origin is used (e.g. pypi.org → TUNA → Aliyun), while the cache key stays pinned to the primary origin.

## Error codes

`E_PROXY_BIND E_PROXY_LOOP E_TOOL_ADAPTER E_RESOLVE_AUTH E_RESOLVE_TIMEOUT E_PRESIGN_EXPIRED E_SSRF_DENIED E_PORT_DENIED E_DIRECT_UNAVAILABLE E_DOCKER_DAEMON E_NOT_CACHEABLE E_TASK_DEAD E_CHECKSUM_MISMATCH E_OUTPUT_EXISTS E_RATE_LIMITED E_REPLAY E_NOT_WHITELISTED`

## Security model

- Egress allowlist: domains only, dot-boundary safe matching; IP literals never match.
- SSRF: loopback/private/link-local/reserved/CGNAT/TEST-NET/multicast blocked on **both** client and server; dial-time validation mitigates DNS rebinding.
- Ports default to 80/443 across the whole chain (tunnel, direct egress, origin fetch).
- Tokens stored hashed; refresh rotates; revocation is immediate; tunnel nonces are single-use per token.
- Presigned URLs are short-lived (15 minutes by default) and refreshable (`POST /api/v1/tasks/:id/refresh`).
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
internal/upstreamproxy             HTTP CONNECT upstream-proxy dialing
deploy/ scripts/                   compose/systemd/examples/build/smoke
```

## Status and limitations (v1.4)

- The Docker Registry mirror is implemented, but **cold pulls need Docker Hub credentials** (anonymous per-IP rate limits are the norm); the client requires `registry-mirrors` in daemon.json plus a dockerd/Docker Desktop restart.
- Full `git clone` is not cached (packfiles are negotiated); use `dldw repo` for snapshots and the tunnel for full history; a bare mirror remains an advanced extension.
- Windows signal forwarding relies on the shared console Ctrl+C; hard kills are not forwarded automatically.
- `apt/dnf/docker` adapters are hint-first; system changes require explicit `--apply` (and root); dockerd is never restarted.
- `direct_fallback: ask` behaves as "no" in non-interactive contexts; pass `--direct-fallback` to opt in.
- Maven/cargo/conda can be wired manually via `/mirror/*`; dedicated injectors are not provided yet.
- The mirror endpoints (`/pypi /npm /mirror /gomod /v2`) are unauthenticated by default: bind to 127.0.0.1 only, or place them in a trusted network / behind a reverse proxy.
