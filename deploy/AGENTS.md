# macOS Deployment Agent Guide

Context for AI agents managing the sub2api deployment on macOS.

> **Dev machine ≠ deployment machine.** This repo is developed on a MacBook. Nginx, sub2api, and all services run on the **Mac Mini (192.168.5.5)**. Never run `nginx -s reload`, `launchctl`, or service commands locally — SSH to 192.168.5.5 first.

---

## Environment

| Item | Value |
|------|-------|
| Host | Mac Mini (2014), x86_64, macOS |
| LAN IP | 192.168.5.5 |
| Domain | sub.liafonx.net (Cloudflare DNS-only, NOT proxied) |
| Install dir | /opt/sub2api |
| Config file | /opt/sub2api/config.yaml |
| Binary | /opt/sub2api/sub2api |
| Service | launchd `com.sub2api` |
| Plist | /Library/LaunchDaemons/com.sub2api.plist |
| Logs | /var/log/sub2api/stdout.log, /var/log/sub2api/stderr.log |
| Nginx | Homebrew Nginx at /usr/local/etc/nginx |
| TLS certs | /usr/local/etc/nginx/cert/liafonx.net/ (wildcard, publicly trusted) |

---

## Architecture

```
Internet
  │
  ▼ :443
┌─────────────────────────────────────────────┐
│  Nginx Stream Multiplexer (ssl_preread)     │
│  SNI: sub.liafonx.net → 127.0.0.1:4435     │
└─────────────┬───────────────────────────────┘
              ▼ :4435
┌─────────────────────────────────────────────┐
│  Nginx HTTP Server Block (sub.conf)         │
│  TLS termination, security headers,         │
│  SSE streaming optimization (gzip off),     │
│  reverse proxy to upstream                  │
└─────────────┬───────────────────────────────┘
              ▼ :9876
┌─────────────────────────────────────────────┐
│  sub2api (Go binary, binds 127.0.0.1:9876)  │
│  API gateway → api.anthropic.com            │
└─────────────────────────────────────────────┘
```

**Note**: The stream multiplexer is a TCP proxy, so `$remote_addr` in the HTTP block is always `127.0.0.1`. Real client IPs are lost unless PROXY protocol is enabled. Per-key auth and rate limiting still work; only IP-based features see 127.0.0.1.

---

## Nginx Configuration

| File | Purpose |
|------|---------|
| `nginx/nginx.conf` | Main config: http block, gzip, logging, includes |
| `nginx/streams-available/stream.conf` | Port 443 SNI multiplexer (TLS+SSH on one port) |
| `nginx/sites-available/sub.conf` | sub2api reverse proxy with SSE streaming |

**Symlink convention**: `sites-enabled/` and `streams-enabled/` contain symlinks to the `-available` directories.

### SSE Streaming Paths

These paths require `gzip off`, `proxy_buffering off`, `proxy_cache off`:

```
/v1/messages
/v1/responses
/responses
/antigravity/v1/messages
/v1beta/models
/antigravity/v1beta/models
```

### Cloudflare DNS

DNS is set to **DNS-only** (grey cloud). Cloudflare proxy was disabled because:
- It buffers SSE streams despite `X-Accel-Buffering: no`
- 524 timeout at 100s idle kills long AI inference requests
- Adds 10-200ms latency with no caching benefit for API traffic

---

## Operational Workflow

### 1. Build from Source

The dev machine is Apple Silicon (ARM). The Mac Mini is x86_64. Always cross-compile:

```bash
# 1. Build frontend (outputs to backend/internal/web/dist/)
cd frontend
pnpm install
pnpm run build

# 2. Cross-compile backend with embedded frontend
cd ../backend
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -tags embed -ldflags "-s -w" -o sub2api ./cmd/server
```

**Critical flags**:
- `-tags embed` — embeds frontend assets; without this, all web UI routes return 404
- `CGO_ENABLED=0` — required for ARM→x86_64 cross-compilation; produces a fully static binary
- `-ldflags "-s -w"` — strips debug info; reduces binary from ~69MB to ~50MB

**Version**: bump `backend/cmd/server/VERSION` before building if needed.

**Always rebuild the frontend first** — a backend-only rebuild embeds stale frontend assets.

### 2. Deploy New Binary

```bash
# Transfer to Mac Mini
scp backend/sub2api user@192.168.5.5:/tmp/sub2api

# On the Mac Mini:
sudo launchctl bootout system/com.sub2api
sudo cp /tmp/sub2api /opt/sub2api/sub2api
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sub2api.plist

# Verify
tail -20 /var/log/sub2api/stderr.log
```

### 3. Service Management

```bash
# Stop
sudo launchctl bootout system/com.sub2api

# Start
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sub2api.plist

# Check status
sudo launchctl print system/com.sub2api

# View logs (structured slog output goes to stderr)
tail -f /var/log/sub2api/stderr.log
```

**Launchd plist settings**: RunAtLoad=true, KeepAlive=true, ThrottleInterval=5s, GIN_MODE=release.

### Config Priority

sub2api uses Viper with `AutomaticEnv()` and `SetEnvKeyReplacer(".", "_")`:

```
Priority: Env vars > config.yaml > defaults
```

The plist previously set `SERVER_HOST` and `SERVER_PORT` env vars which silently overrode config.yaml. These were removed — config.yaml is now the single source of truth for all settings except `GIN_MODE`.

---

## Tuning (4 Users)

Peak concurrency: 4 users × 2 sessions × (1 main + 3 subagents) = **32**

| Setting | Value | Rationale |
|---------|-------|-----------|
| `default.user_concurrency` | 10 | 2 sessions × 4 = 8, +2 headroom |
| `rate_limit.requests_per_minute` | 200 | 4 users × 2 sessions × ~20 RPM |
| `rate_limit.burst_size` | 30 | Handle subagent burst |
| `gateway.max_idle_conns` | 60 | Enough for 4-user setup |
| `gateway.max_idle_conns_per_host` | 40 | Match peak upstream connections |
| `gateway.max_conns_per_host` | 80 | 2x peak for safety margin |
| `gateway.idle_conn_timeout_seconds` | 180 | Keep connections warm longer |
| `gateway.connection_pool_isolation` | "account" | Few accounts, no per-account proxy needed |

---

## Fork-Only Patches

This deployment runs `liafonx/sub2api` (fork of `Wei-Shaw/sub2api`). The following patches are not in upstream.

### Patch 1: TLS Fingerprint Registry Fix

**Problem**: `InitGlobalRegistry()` was never called — config profiles were silently ignored and only the built-in default was used.

**Fix**: Call `InitGlobalRegistry(&cfg.Gateway.TLSFingerprint)` in `NewHTTPUpstream()` in `backend/internal/repository/http_upstream.go`.

**Upstream status**: NOT fixed as of v0.1.85. PR submitted: https://github.com/Wei-Shaw/sub2api/pull/611

#### TLS Fingerprint Profile Selection

Profiles are selected deterministically: `accountID % numProfiles` (sorted alphabetically by key name).

To override the built-in default, use the key `claude_cli_v2` in config.yaml:

```yaml
gateway:
  tls_fingerprint:
    enabled: true
    profiles:
      claude_cli_v2:
        name: "Your Custom Profile Name"
        cipher_suites: [...]
        curves: [...]
        point_formats: [...]
```

### Patch 2: HTTP/2 Upstream (added 2026-03-02)

**Problem**: Go's standard `http.Transport` with `ForceAttemptHTTP2: true` breaks when using a custom `DialTLSContext` returning `*utls.UConn`. Go's HTTP/2 handler does a `*tls.Conn` type assertion that silently fails, causing the server (which agreed to h2 via ALPN) to send HTTP/2 binary frames while the client parses them as HTTP/1.x — 100% request failures.

**Fix**: `NewH2RoundTripper` in `backend/internal/pkg/tlsfingerprint/h2_roundtripper.go`:
1. First request to a host: dials with utls, reads `NegotiatedProtocol` from TLS state
2. If `"h2"`: creates `golang.org/x/net/http2.Transport` (accepts `net.Conn`, no `*tls.Conn` assertion)
3. If other: creates `http.Transport{ForceAttemptHTTP2: false}` with existing pool settings
4. Caches the transport per host — all subsequent requests skip the probe

**Files changed**:

| File | Change |
|------|--------|
| `backend/internal/pkg/tlsfingerprint/h2_roundtripper.go` | **NEW** — Hybrid protocol-detecting RoundTripper |
| `backend/internal/pkg/tlsfingerprint/h2_roundtripper_test.go` | **NEW** — Unit tests |
| `backend/internal/pkg/tlsfingerprint/dialer.go` | ALPN changed from `["http/1.1"]` to `["h2", "http/1.1"]` |
| `backend/internal/repository/http_upstream.go` | `buildUpstreamTransportWithTLSFingerprint` now returns `http.RoundTripper` |

`golang.org/x/net/http2` was already a transitive dependency — no go.mod changes needed.

**Confirmed impact** (verified 2026-03-03): HTTP/2 multiplexing active — `h2_transport_created host=api.anthropic.com:443` observed on first request. N concurrent requests share 1 TCP+TLS connection vs N separate. JA3 fingerprint gains `h2` in ALPN, matching Node.js v22 behavior.

#### Verifying After Deploy

Make one request, then check (no config changes needed — transport logs write directly to stderr):

```bash
# Should appear once per upstream host on first request:
grep "h2_transport_created\|h1_transport_created" /var/log/sub2api/stderr.log

# Should NOT appear:
grep "malformed HTTP\|transport: received unexpected" /var/log/sub2api/stderr.log
```

Confirmed: `h2_transport_created host=api.anthropic.com:443`

---

## Fork Maintenance (Syncing Upstream)

```bash
git fetch upstream
git merge upstream/main
# Resolve conflicts (typically VERSION and .gitignore)

# Always align the fork's version with the latest upstream tag:
# 1) Find newest tag: git tag --list 'v*' --sort=-creatordate | head -n 1
# 2) Strip the leading 'v' and update backend/cmd/server/VERSION to that value.
# 3) Commit the VERSION bump on the merge branch.

# Verify fork-only patches survived:
grep InitGlobalRegistry backend/internal/repository/http_upstream.go
grep '"h2"' backend/internal/pkg/tlsfingerprint/dialer.go
ls backend/internal/pkg/tlsfingerprint/h2_roundtripper.go
# Rebuild frontend + backend, deploy
```

---

## Debug Mode

Two separate debug settings with different effects:

- `server.mode: "debug"` — enables GIN route debug output (HTTP routing info) only
- `log.level: "debug"` — enables slog/zap debug messages (TLS negotiation, registry init, etc.); Debug+Info logs go to **stdout.log**, Warn+ logs go to **stderr.log**

Note: H2/H1 transport creation logs (`h2_transport_created`/`h1_transport_created`) write directly to stderr via `fmt.Fprintf(os.Stderr, ...)` — always visible regardless of `log.level`, always in **stderr.log**. `slog.Debug(...)` calls in the DoWithTLS flow (e.g., `tls_fingerprint_enabled`) still require `log.level: "debug"` and go to stdout.log.

Steps (for deeper debug logging):
1. Set `log.level: "debug"` in config.yaml (and optionally `server.mode: "debug"`)
2. Restart sub2api
3. Check logs: `grep tls_registry /var/log/sub2api/stdout.log`
4. **Reset `log.level` to `"info"` afterward** — debug logging is verbose

---

## Known Issues

1. **Real IP lost at stream multiplexer**: HTTP block always sees `$remote_addr` as 127.0.0.1. Enable PROXY protocol in both `stream.conf` and `sub.conf` to restore real client IPs.

2. **Env var silently overrides config**: Any env var matching `SECTION_KEY` pattern overrides config.yaml. Check the launchd plist if config changes don't take effect.

3. **TTFT is upstream latency**: Time-to-first-token (P99 ~3-4s) is normal AI inference time. Proxy overhead is ~44ms — no optimization needed on the proxy side.

4. **Cloudflare proxy breaks SSE**: If DNS is ever switched to proxied mode, AI streaming will degrade. Keep DNS-only.

5. **Frontend rebuild required**: Always rebuild the frontend before the backend. A backend-only rebuild embeds stale frontend assets.
