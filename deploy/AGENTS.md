<!-- This file is symlinked as CLAUDE.md. AGENTS.md and CLAUDE.md are the same file. -->

# Deployment Agent Guide

Context for AI agents managing the sub2api deployments.

> **Dev machine ≠ deployment machine.** This repo is developed on a MacBook. Never run service commands locally.
>
> **Deployment target policy:** **`88.151.34.29` (VPS) is the testing machine** and is the default deployment target. Always deploy to the VPS unless the user explicitly asks to deploy to the **Mac Mini**, which is the **production machine**.

---

## Target Selection

| Machine | Role | Default? | When to use |
|------|-------|----------|-------------|
| `88.151.34.29` (VPS) | Testing | Yes | Use for normal deploys, validation, and staging changes before production |
| Mac Mini | Production | No | Use only when the user explicitly requests a production deploy |

---

## Testing Environment (`88.151.34.29` — VPS)

| Item | Value |
|------|-------|
| Host | `88.151.34.29`, x86_64, Debian Linux |
| SSH | `liafonx@88.151.34.29` |
| Role | Testing machine (default deploy target) |
| Binary | /opt/sub2api/sub2api (owned by `sub2api:sub2api`) |
| Data/Config dir | /opt/sub2api/ |
| Config file | /opt/sub2api/config.yaml |
| Service | systemd `sub2api.service` |
| Caddy | systemd `caddy.service` |
| Caddy config | /etc/caddy/Caddyfile |
| Caddy sub config | /etc/caddy/sites-available/sub.liafonx.net.caddy |
| TLS certs | /etc/caddy/certs/sub.liafonx.net/ |

### VPS sudo permissions (`/etc/sudoers.d/sub2api-deploy`)

`liafonx` has passwordless sudo for exactly these four commands (no others):

```
liafonx ALL=(ALL) NOPASSWD: /bin/systemctl stop sub2api, /bin/systemctl start sub2api, /bin/cp /tmp/sub2api /opt/sub2api/sub2api, /bin/chmod +x /opt/sub2api/sub2api
```

- `sudo systemctl restart sub2api` — **NOT** NOPASSWD; use `stop` + `start` separately
- `sudo systemctl status sub2api` — **NOT** NOPASSWD; use `journalctl` instead
- `journalctl -u sub2api` — no sudo needed (`liafonx` is in `systemd-journal` group)

## Production Environment (Mac Mini)

| Item | Value |
|------|-------|
| Host | Mac Mini (2014), x86_64, macOS |
| SSH | `liafonx@Liafonxs-Mac-mini.local` (prefer over IP) |
| LAN IP | 192.168.5.5 |
| Domain | sub.liafonx.net (Cloudflare DNS-only, NOT proxied) |
| Binary | /usr/local/bin/sub2api |
| Data/Config dir | /usr/local/var/sub2api/ |
| Config file | /usr/local/var/sub2api/config.yaml |
| Service | launchd `com.sub2api` (LaunchAgent, runs as liafonx) |
| Plist | ~/Library/LaunchAgents/com.sub2api.plist |
| Logs | /usr/local/var/log/sub2api/sub2api.log (app), /usr/local/var/log/sub2api/stderr.log (panics/transport) |
| Caddy | Homebrew Caddy 2.11.2 at /usr/local/opt/caddy/bin/caddy (runs as root, LaunchDaemon) |
| Caddy config | /usr/local/etc/caddy/Caddyfile (imports sites-available/*.caddy) |
| Caddy sub config | /usr/local/etc/caddy/sites-available/sub.caddy |
| Caddy logs | /usr/local/var/log/caddy/sub_access.log (JSON) |
| TLS certs | /usr/local/etc/caddy/cert/liafonx.net/ (wildcard, publicly trusted) |

---

## Architecture

```
Internet
  │
  ▼ :443
┌─────────────────────────────────────────────┐
│  Caddy (sub.liafonx.net)                   │
│  TLS termination, security headers,         │
│  SSE streaming (flush_interval -1),         │
│  zstd/gzip compression (non-SSE paths),     │
│  reverse proxy to upstream                  │
└─────────────┬───────────────────────────────┘
              ▼ :9876
┌─────────────────────────────────────────────┐
│  sub2api (Go binary, binds 0.0.0.0:9876)    │
│  API gateway → api.anthropic.com            │
└─────────────────────────────────────────────┘
```

Caddy connects to sub2api via h2c (cleartext HTTP/2) with `versions h2c 2` transport — no TLS between Caddy and sub2api. Real client IPs are available (Caddy does direct TLS termination, not TCP proxying).

Current Mac Mini testing config exposes sub2api on the LAN as well:
- sub2api bind: `0.0.0.0:9876`
- LAN health check: `http://192.168.5.5:9876/health`
- Public entrypoint remains Caddy at `https://sub.liafonx.net`

---

## Caddy Configuration

| File | Purpose |
|------|---------|
| `/usr/local/etc/caddy/Caddyfile` | Root config: global options, imports sites-available/*.caddy |
| `/usr/local/etc/caddy/sites-available/sub.caddy` | sub2api reverse proxy (SSE, compression, security headers) |
| `/usr/local/etc/caddy/sites-available/qb.caddy` | qBittorrent reverse proxy |
| `/usr/local/etc/caddy/cert/liafonx.net/` | Wildcard TLS cert (fullchain.pem + privkey.pem) |

**Service**: Homebrew LaunchDaemon (`homebrew.mxcl.caddy`), runs as root. Managed via `brew services`.

```bash
# On Mac Mini:
sudo brew services restart caddy
sudo brew services stop caddy
sudo brew services start caddy
sudo caddy reload --config /usr/local/etc/caddy/Caddyfile   # hot reload without downtime
```

### SSE Streaming Paths

These paths use the `@sse` matcher with `flush_interval -1` (immediate flush) and h2c transport. No compression on these paths:

```
/v1/messages
/v1/responses
/responses
/antigravity/v1/messages
/v1beta/models
/antigravity/v1beta/models
```

All other paths get `encode zstd gzip` compression.

### Caddy → sub2api Transport

Both SSE and default handles use `versions h2c 2` — Caddy speaks cleartext HTTP/2 to sub2api on port 9876. Timeouts: `dial_timeout 30s`, `response_header_timeout 300s`. Default handle also sets `keepalive 120s`, `keepalive_idle_conns 64`.

### Cloudflare DNS

DNS is set to **DNS-only** (grey cloud). Cloudflare proxy was disabled because:
- It buffers SSE streams despite `X-Accel-Buffering: no`
- 524 timeout at 100s idle kills long AI inference requests
- Adds 10-200ms latency with no caching benefit for API traffic

---

## Operational Workflow

### 1. Build from Source

The dev machine is Apple Silicon (ARM). Both deployment targets are x86_64 but different OS.

```bash
# 1. Build frontend (outputs to backend/internal/web/dist/)
cd frontend
pnpm install
pnpm run build

# 2a. Cross-compile for Testing VPS (Linux amd64) — DEFAULT
cd ../backend
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embed -ldflags "-s -w" -o sub2api ./cmd/server

# 2b. Cross-compile for Production Mac Mini (darwin amd64) — only when explicitly requested
cd ../backend
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -tags embed -ldflags "-s -w" -o sub2api ./cmd/server
```

**Critical flags**:
- `-tags embed` — embeds frontend assets; without this, all web UI routes return 404
- `CGO_ENABLED=0` — required for ARM→x86_64 cross-compilation; produces a fully static binary
- `-ldflags "-s -w"` — strips debug info; reduces binary from ~69MB to ~50MB

**Version**: bump `backend/cmd/server/VERSION` before building if needed.

**Always rebuild the frontend first** — a backend-only rebuild embeds stale frontend assets.

### 2. Deploy New Binary (Default: Testing / VPS)

```bash
# Transfer to VPS testing machine (from repo root).
scp -o ServerAliveInterval=10 -o ServerAliveCountMax=2 backend/sub2api liafonx@88.151.34.29:/tmp/sub2api

# On the VPS (SSH in first: ssh liafonx@88.151.34.29):
sudo systemctl stop sub2api
sudo cp /tmp/sub2api /opt/sub2api/sub2api
sudo systemctl start sub2api

# Verify (journalctl needs no sudo — liafonx is in systemd-journal group)
journalctl -u sub2api -n 30 --no-pager
```

### 2b. Deploy New Binary (Production / Mac Mini — only when explicitly requested)

```bash
# Transfer to Mac Mini production machine (from repo root).
scp -o ServerAliveInterval=10 -o ServerAliveCountMax=2 backend/sub2api liafonx@Liafonxs-Mac-mini.local:/tmp/sub2api

# On the Mac Mini (SSH in first: ssh liafonx@Liafonxs-Mac-mini.local):
launchctl bootout gui/$(id -u)/com.sub2api
cp /tmp/sub2api /usr/local/bin/sub2api
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sub2api.plist

# Verify
tail -20 /usr/local/var/log/sub2api/sub2api.log
```

### 3. Service Management (VPS Testing)

```bash
# Stop (NOPASSWD — no password prompt)
sudo systemctl stop sub2api

# Start (NOPASSWD — no password prompt)
sudo systemctl start sub2api

# Restart — NOT NOPASSWD; use stop + start instead
sudo systemctl stop sub2api && sudo systemctl start sub2api

# Check status — NOT NOPASSWD; use journalctl instead
journalctl -u sub2api -n 30 --no-pager   # no sudo needed (systemd-journal group)

# View logs (no sudo needed)
journalctl -u sub2api -f
```

### 3b. Service Management (Mac Mini Production)

```bash
# Stop (no sudo needed — user-domain LaunchAgent)
launchctl bootout gui/$(id -u)/com.sub2api

# Start
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sub2api.plist

# Check status
launchctl print gui/$(id -u)/com.sub2api

# View logs (structured logs in sub2api.log, transport/panic in stderr.log)
tail -f /usr/local/var/log/sub2api/sub2api.log
```

**Launchd plist settings (Mac Mini)**: RunAtLoad=true, KeepAlive=true, ThrottleInterval=5s, GIN_MODE=release, WorkingDirectory=/usr/local/var/sub2api (Viper finds config.yaml via cwd). No UserName or Umask keys (inherits liafonx session).

### Config Priority

sub2api uses Viper with `AutomaticEnv()` and `SetEnvKeyReplacer(".", "_")`:

```
Priority: Env vars > config.yaml > defaults
```

The plist sets only `GIN_MODE=release`. `DATA_DIR` is not set — Viper finds `config.yaml` via `WorkingDirectory=/usr/local/var/sub2api` (the cwd fallback in `config.go`). config.yaml is the single source of truth for all settings except `GIN_MODE`.

---

## Tuning (deploy/config.yaml)

Current tuning is defined by `deploy/config.yaml`, sized for the Mac Mini's normal active-use role. The machine remains the default testing target, but the temporary low-resource profile is no longer the live baseline.

### Infrastructure tuning (on Mac Mini)

| Service | Setting | Value | Rationale |
|---------|---------|-------|-----------|
| PostgreSQL | `max_connections` | `32` | 24 sub2api + headroom for admin/internal connections |
| PostgreSQL | `shared_buffers` | `128MB` | Fits the active dataset without oversizing on 8GB RAM |
| PostgreSQL | `work_mem` | `2MB` | Enough for normal sorts/aggregations without runaway memory |
| PostgreSQL | `maintenance_work_mem` | `64MB` | Faster VACUUM/index maintenance on usage tables |
| PostgreSQL | `effective_cache_size` | `1GB` | Reflects meaningful OS cache availability |
| Redis | `maxmemory` | unset | No artificial 64MB cap during normal use |
| Redis | `maxmemory-policy` | default | Avoids forced eviction under normal working set size |
| Redis | `save` | default | Restores standard persistence cadence |
| Redis | `hz` | `10` | Restores normal housekeeping frequency |
| Redis | `timeout` | `0` | Keeps clients connected unless they disconnect |

### sub2api config key values

| Setting | Value | Rationale |
|---------|-------|-----------|
| `default.user_concurrency` | `6` | Restores normal per-user headroom |
| `database.max_open_conns` | `24` | Fits within PG `max_connections=32` |
| `database.max_idle_conns` | `12` | Half of open pool |
| `redis.pool_size` | `64` | Restores normal Redis client pool size |
| `redis.min_idle_conns` | `8` | Keeps enough warm Redis connections |
| `gateway.max_idle_conns` | `60` | Matches the restored upstream concurrency target |
| `gateway.max_conns_per_host` | `60` | Prevents host-level throttling under normal use |
| `gateway.max_upstream_clients` | `50` | Adequate client cache for the account set |
| `gateway.idle_conn_timeout_seconds` | `120` | Longer idle lifetime reduces reconnect churn |
| `gateway.usage_record.worker_count` | `8` | Restores normal async usage write throughput |
| `gateway.usage_record.queue_size` | `256` | Enough burst buffer for real traffic |
| `gateway.scheduling.sticky_session_max_waiting` | `9` | Restores practical sticky-session queue depth |
| `gateway.scheduling.fallback_max_waiting` | `54` | Matches the restored queue capacity target |
| `gateway.scheduling.full_rebuild_interval_seconds` | `120` | Faster scheduling recovery under real load |
| `server.h2c.max_concurrent_streams` | `50` | Restores the normal h2c multiplexing level |
| `api_key_auth_cache.l1_size` | `1024` | Restores a practical hot-cache size |
| `log.rotation.max_size_mb` | `5` | Keep file rotation conservative on the Mac Mini |
| `log.rotation.max_backups` | `3` | Keep log retention bounded |

### Restore / Revert

Backups created 2026-03-30:
- `/usr/local/var/postgresql@16/postgresql.conf.bak.20260330`
- `/usr/local/etc/redis.conf.bak.20260330`
- `/usr/local/var/sub2api/config.yaml.bak.20260330`

Restore from `.bak.20260330` files to return to the pre-2026-03-30 normal-use baseline, then restart in order: PG → Redis → sub2api.

When changing tuning, update `deploy/config.yaml` first and treat this table as a summary of the live config, not a second source of truth.

---

## Repo Context

This deployment guide is intentionally deployment-only.

For non-deployment repo context, use:
- Root branch/state guide: **[`../AGENTS.md`](../AGENTS.md)**
- Fork patch catalog and verification checklist: **[`../ACTIVE_PATCHES.md`](../ACTIVE_PATCHES.md)**

Current repo model:
- `main` is at upstream `v0.1.112` + 11 active fork patches
- old fork `main` is archived on `archive/fork-main-pre-clean-migration-2026-03-28`

Do not duplicate fork patch inventories or upstream-merge playbooks here; keep this file focused on machine topology, config locations, service management, deployment, and runtime debugging.

---

## Debug Mode

Two separate debug settings with different effects:

- `server.mode: "debug"` — enables GIN route debug output (HTTP routing info) only
- `log.level: "debug"` — enables slog/zap debug messages (TLS negotiation, registry init, etc.); all structured logs go to **sub2api.log**

Note: H2/H1 transport creation logs (`h2_transport_created`/`h1_transport_created`) write directly to stderr via `fmt.Fprintf(os.Stderr, ...)` — always visible regardless of `log.level`, always in **stderr.log**. `slog.Debug(...)` calls in the DoWithTLS flow (e.g., `tls_fingerprint_enabled`) still require `log.level: "debug"` and go to sub2api.log.

Steps (for deeper debug logging):
1. Set `log.level: "debug"` in config.yaml (and optionally `server.mode: "debug"`)
2. Restart sub2api
3. Check logs: `grep tls_registry /usr/local/var/log/sub2api/sub2api.log`
4. **Reset `log.level` to `"info"` afterward** — debug logging is verbose

---

## Known Issues

1. **Real IP available**: Caddy does direct TLS termination (no TCP stream proxy), so sub2api sees real client IPs in `X-Forwarded-For`. No PROXY protocol needed.

2. **Env var silently overrides config**: Any env var matching `SECTION_KEY` pattern overrides config.yaml. Check the launchd plist if config changes don't take effect.

3. **TTFT is upstream latency**: Time-to-first-token (P99 ~3-4s) is normal AI inference time. Proxy overhead is ~44ms — no optimization needed on the proxy side.

4. **Cloudflare proxy breaks SSE**: If DNS is ever switched to proxied mode, AI streaming will degrade. Keep DNS-only.

5. **Frontend rebuild required**: Always rebuild the frontend before the backend. A backend-only rebuild embeds stale frontend assets.
