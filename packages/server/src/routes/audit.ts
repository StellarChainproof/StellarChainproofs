import { Router, Response } from "express";
import { AuditLogger } from "@chainproof/core";
import { AuthenticatedRequest, requireScope } from "../middleware/auth";

export function createAuditRouter(auditLogger: AuditLogger): Router {
  const router = Router();

  router.get("/", requireScope("audit:read"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const { type, status, principalId, since, until, limit, offset } = req.query;

    const tenantId = principal.roles.includes("admin") && req.query.tenantId ? (req.query.tenantId as string) : principal.tenantId;

    const result = auditLogger.query({
      tenantId,
      projectId: req.query.projectId as string,
      principalId: principalId as string,
      type: type as any,
      status: status as any,
      sinceTimestamp: since ? parseInt(since as string, 10) : undefined,
      untilTimestamp: until ? parseInt(until as string, 10) : undefined,
      limit: limit ? parseInt(limit as string, 10) : 50,
      offset: offset ? parseInt(offset as string, 10) : 0,
    });

    res.json(result);
  });

  return router;
}
