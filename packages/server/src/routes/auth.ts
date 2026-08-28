import { Router, Response } from "express";
import { ApiKeyManager, AuditLogger } from "@chainproof/core";
import { AuthenticatedRequest, requireScope } from "../middleware/auth";

export interface AuthRouterOptions {
  apiKeyManager: ApiKeyManager;
  auditLogger?: AuditLogger;
}

export function createAuthRouter(options: AuthRouterOptions): Router {
  const router = Router();
  const { apiKeyManager, auditLogger } = options;

  router.post("/keys", requireScope("keys:manage"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const body = req.body ?? {};

    const name = body.name ?? "API Key";
    const tenantId = principal.roles.includes("admin") && body.tenantId ? body.tenantId : principal.tenantId;

    const { rawKey, record } = apiKeyManager.createApiKey({
      tenantId,
      projectId: body.projectId ?? principal.projectId,
      name,
      roles: body.roles,
      scopes: body.scopes,
      expiresInMs: body.expiresInMs,
      rateLimitTier: body.rateLimitTier,
    });

    if (auditLogger) {
      auditLogger.record({
        type: "auth.key_created",
        tenantId,
        principalId: principal.id,
        action: "key.create",
        status: "success",
        details: { keyId: record.id, keyName: name },
      });
    }

    res.status(201).json({
      rawKey,
      key: record,
    });
  });

  router.get("/keys", requireScope("keys:manage"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const tenantId = principal.roles.includes("admin") && req.query.tenantId ? (req.query.tenantId as string) : principal.tenantId;

    const keys = apiKeyManager.listKeysForTenant(tenantId);
    res.json({ keys, total: keys.length });
  });

  router.post("/keys/rotate", requireScope("keys:manage"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const { keyId, gracePeriodMs } = req.body ?? {};

    if (!keyId) {
      res.status(400).json({ error: "Missing required field: keyId" });
      return;
    }

    const key = apiKeyManager.getKey(keyId);
    if (!key) {
      res.status(404).json({ error: `API key not found: ${keyId}` });
      return;
    }

    if (!principal.roles.includes("admin") && key.tenantId !== principal.tenantId) {
      res.status(403).json({ error: "Access denied to API key" });
      return;
    }

    try {
      const { newRawKey, newRecord, oldRecord } = apiKeyManager.rotateKey({ keyId, gracePeriodMs });

      if (auditLogger) {
        auditLogger.record({
          type: "auth.key_rotated",
          tenantId: key.tenantId,
          principalId: principal.id,
          action: "key.rotate",
          status: "success",
          details: { oldKeyId: oldRecord.id, newKeyId: newRecord.id },
        });
      }

      res.json({
        newRawKey,
        newKey: newRecord,
        oldKey: oldRecord,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  router.delete("/keys/:id", requireScope("keys:manage"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const keyId = req.params.id;
    const reason = req.body?.reason ?? "Revoked by user";

    const key = apiKeyManager.getKey(keyId);
    if (!key) {
      res.status(404).json({ error: `API key not found: ${keyId}` });
      return;
    }

    if (!principal.roles.includes("admin") && key.tenantId !== principal.tenantId) {
      res.status(403).json({ error: "Access denied to API key" });
      return;
    }

    const revokedKey = apiKeyManager.revokeKey(keyId, reason);

    if (auditLogger) {
      auditLogger.record({
        type: "auth.key_revoked",
        tenantId: key.tenantId,
        principalId: principal.id,
        action: "key.revoke",
        status: "success",
        details: { keyId, reason },
      });
    }

    res.json({ message: `API key ${keyId} revoked successfully`, key: revokedKey });
  });

  return router;
}
