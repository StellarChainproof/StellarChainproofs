# feat: REST API server mode (`chainproof serve`) — issue #25

## Summary

Adds a new `packages/server` package that exposes ChainProof's scanning engine as a standalone HTTP REST API, along with a `chainproof serve` CLI command to start it. This allows thin clients — Python CI pipelines, browser-based editors, remote dev containers, and future IDE extensions in other languages — to scan Solidity contracts without requiring a local Node.js toolchain.

---

## What Changed

### New: `packages/server`

| File | Purpose |
|------|---------|
| `src/server.ts` | Express application factory (`createApp`) and `startServer` entry-point |
| `src/routes/health.ts` | `GET /health` — liveness probe |
| `src/routes/scan.ts` | `POST /scan` (inline content) and `POST /scan/file` (server FS, gated by `--allow-fs`) |
| `src/routes/rules.ts` | `GET /rules` — rule metadata |
| `src/rules-registry.ts` | Static registry of all built-in rule metadata |
| `openapi.yaml` | Full OpenAPI 3.1 specification |
| `package.json` / `tsconfig.json` | Package config, extends workspace tsconfig |

### Updated: `packages/cli`

- Added `chainproof serve` command with flags: `--port`, `--host`, `--token`, `--allow-fs`, `--max-requests`, `--body-limit`
- Server package is dynamically imported so existing scan/check/init commands have zero startup overhead

### New: `examples/docker/`

- `Dockerfile` — multi-stage build (builder → slim runtime)
- `docker-compose.yml` — ready-to-run compose file with health check, env-var configuration hints, and `--allow-fs` / `--token` toggle comments

---

## API Reference (quick)

```
POST /scan          — scan inline Solidity source, returns ScanResult JSON
POST /scan/file     — scan server-side path (requires --allow-fs)
GET  /health        — { status, version, slitherAvailable }
GET  /rules         — array of { id, title, severity, category, description }
```

Full spec: [`packages/server/openapi.yaml`](packages/server/openapi.yaml)

---

## Security

| Feature | Default | Flag / Env |
|---------|---------|-----------|
| Bearer token auth | off (localhost) | `--token <secret>` / `CHAINPROOF_TOKEN` |
| Rate limiting | 10 req/min | `--max-requests <n>` / `CHAINPROOF_MAX_REQUESTS` |
| Request size limit | 5 MB | `--body-limit <size>` / `CHAINPROOF_BODY_LIMIT` |
| Filesystem access | disabled | `--allow-fs` |
| Directory traversal | sanitized | `path.basename()` applied to inline file paths |

---

## Usage Examples

**Start locally**
```bash
chainproof serve --port 4243
```

**With auth and filesystem access**
```bash
chainproof serve --port 4243 --host 0.0.0.0 --token mysecret --allow-fs
```

**Docker**
```bash
cd examples/docker
docker compose up
```

**Scan from Python**
```python
import requests, json

resp = requests.post("http://localhost:4243/scan", json={
    "files": [{"path": "Vault.sol", "content": open("Vault.sol").read()}],
    "config": {"minSeverity": "medium"}
})
result = resp.json()
print(json.dumps(result["summary"], indent=2))
```

**Scan from curl**
```bash
curl -s -X POST http://localhost:4243/scan \
  -H "Content-Type: application/json" \
  -d '{"files":[{"path":"Test.sol","content":"pragma solidity ^0.7.0; contract T {}"}]}' \
  | jq .summary
```

---

## Acceptance Criteria Checklist

- [x] `packages/server` scaffold with Express
- [x] `POST /scan` accepts inline file contents and returns `ScanResult`
- [x] `GET /health` endpoint
- [x] `GET /rules` endpoint returning rule metadata
- [x] `chainproof serve` CLI command with `--port`, `--host`, `--token` flags
- [x] Rate limiting middleware (configurable, default 10 req/min)
- [x] Request size limiting (configurable, default 5 MB)
- [x] Bearer token authentication (optional, off by default on localhost)
- [x] `POST /scan/file` gated by `--allow-fs` flag
- [x] Docker example in `examples/docker/` with `Dockerfile` and `docker-compose.yml`
- [x] OpenAPI spec for the server API (`packages/server/openapi.yaml`)

---

Closes #25
