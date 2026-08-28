# ChainProof REST Server Hardening & Multi-Tenant Controls

This document details the production-grade architecture, authentication primitives, durable priority job queue, tenant sandboxing, quota controls, error sanitization, and operational monitoring interfaces added to the ChainProof REST Server.

---

## 1. Security Architecture & Threat Model

### Security Boundaries
The ChainProof REST Server acts as a multi-tenant analysis platform where untrusted users can submit arbitrary Solidity source files or archive payloads. To protect against malicious or adversarial payloads, the server implements strict security boundaries:

1. **Authentication Boundary**: Principals are verified via prefixed API keys (`cp_live_...`) hashed with SHA-256 or via OIDC claims (JWTs).
2. **Authorization Boundary**: Scope-based RBAC (`scan:create`, `scan:read`, `scan:cancel`, `scan:delete`, `jobs:manage`, `metrics:read`, `audit:read`, `keys:manage`, `tenant:manage`).
3. **Execution Sandbox Boundary**: Scans run in isolated, single-use per-job file sandboxes (`chainproof-sandboxes/tenant-<id>/job-<id>`) with scrubbed environment variables.
4. **Archive & Bomb Safeguards**: `.zip` archive payloads undergo strict compression ratio checks (max 100:1), uncompressed size limits (max 50MB aggregate, 10MB per file), file count caps (max 500), and path traversal checks (`..`, absolute paths, symlinks).
5. **Data Sanitization & Privacy Boundary**: Errors, stack traces, and findings are scrubbed of host filesystem paths, API keys, and environment secrets before being returned to clients or logged in audit stores.
6. **LLM Transmission Policy Boundary**: Source code transmission to external LLM providers is disabled by default (`allowLLM: false`).

---

## 2. Authentication & Principal RBAC

### Principals & Roles
- **Roles**: `admin`, `tenant-admin`, `operator`, `viewer`.
- **Scopes**:
  - `scan:create`: Submit synchronous or queued scans.
  - `scan:read`: Read scan progress, status, and findings.
  - `scan:cancel`: Request job cancellation.
  - `scan:delete`: Delete job records and results.
  - `jobs:manage`: Manage worker queue and job retention.
  - `metrics:read`: Read queue, quota, and server metrics.
  - `audit:read`: Query tenant audit logs.
  - `keys:manage`: Create, rotate, or revoke API keys.

### API Key Lifecycle & Rotation
- **Prefix**: All production API keys begin with `cp_live_`.
- **Rotation**: Key rotation (`POST /auth/keys/rotate`) issues a new key while maintaining a configurable grace period (default: 24h) during which the retiring key remains valid for smooth client migration.
- **Revocation**: Key revocation (`DELETE /auth/keys/:id`) immediately invalidates a key and logs the revocation reason.

---

## 3. Durable Priority Job Queue & Worker Architecture

### Job Lifecycle
`queued` ➔ `running` ➔ (`completed` | `failed` | `cancelled` | `timed_out`)

- **Priorities**: 0 (Critical/Urgent) to 3 (Low). Jobs are dequeued strictly in order of priority, then submission time.
- **Idempotency**: Submitting with an `idempotencyKey` returns the existing job if submitted within the active retention window.
- **Leases & Heartbeats**: Workers acquire a timed lease (default: 30s) and send periodic heartbeats (default: 5s).
- **Crash Recovery**: Stale leases (due to worker crash or unhandled process termination) are automatically detected during periodic sweeps and requeued if `attempts < maxRetries`.
- **Cancellation**: Jobs can be cancelled at any point (`POST /jobs/:id/cancel`). AbortSignals terminate running worker tasks and clean up sandbox temp directories.
- **Status Streaming**: Server-Sent Events (SSE) stream progress (`GET /jobs/:id/stream`) in real-time.

---

## 4. Multi-Tenant Quota & Resource Controls

Per-tenant resource quotas are actively enforced with structured JSON error responses:

- **Max Concurrent Jobs**: Default 2 active jobs per tenant.
- **Submission Rate Limits**: Default 100 job submissions per hour.
- **Storage Limits**: Default 500MB total stored results per tenant.
- **Compute Time Limits**: Cumulative CPU scan duration limit per tenant window.

When a quota is exceeded, the server returns HTTP `429 Too Many Requests` or `413 Payload Too Large` with a structured payload:

```json
{
  "error": "Tenant 'tenant-acme' has reached maximum concurrent job limit (2/2)",
  "code": "QUOTA_EXCEEDED_CONCURRENCY",
  "tenantId": "tenant-acme",
  "metric": "concurrency",
  "limit": 2,
  "current": 2,
  "retryAfterSeconds": 15
}
```

---

## 5. API Reference

### Health & Readiness
- `GET /health/live`: Liveness check.
- `GET /health/ready`: System readiness check, returning queue health and Slither status.

### Scan & Job Management
- `POST /scan`: Synchronous scan with inline files or zip payload.
- `POST /jobs`: Queue scan job (accepts `files` array or `archiveBase64`, `priority`, `idempotencyKey`).
- `GET /jobs`: Paginated job list (filtered by tenant, status, search query).
- `GET /jobs/:id`: Single job status and result.
- `GET /jobs/:id/stream`: SSE progress and completion stream.
- `POST /jobs/:id/cancel`: Cancel job execution.
- `DELETE /jobs/:id`: Delete job result and record.

### Key Management & Operations
- `POST /auth/keys`: Generate API key.
- `GET /auth/keys`: List API keys for tenant.
- `POST /auth/keys/rotate`: Rotate API key with grace period.
- `DELETE /auth/keys/:id`: Revoke API key.
- `GET /audit`: Query audit logs.
- `GET /metrics`: Fetch queue, quota usage, and process metrics.
