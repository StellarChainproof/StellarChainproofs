import { Router, Response } from "express";
import { JobQueueManager, QuotaManager } from "@chainproof/core";
import { AuthenticatedRequest, requireScope } from "../middleware/auth";

export function createMetricsRouter(queueManager: JobQueueManager, quotaManager: QuotaManager): Router {
  const router = Router();

  router.get("/", requireScope("metrics:read"), (req: AuthenticatedRequest, res: Response): void => {
    const principal = req.principal!;
    const tenantId = principal.roles.includes("admin") && req.query.tenantId ? (req.query.tenantId as string) : principal.tenantId;

    const queueStats = queueManager.getStats(principal.roles.includes("admin") ? undefined : tenantId);
    const quotaUsage = quotaManager.getTenantUsage(tenantId, queueManager);
    const quotaLimits = quotaManager.getTenantLimits(tenantId);

    res.json({
      tenantId,
      queue: queueStats,
      quota: {
        usage: quotaUsage,
        limits: quotaLimits,
      },
      system: {
        uptimeSeconds: Math.floor(process.uptime()),
        memoryUsage: process.memoryUsage(),
      },
      timestamp: Date.now(),
    });
  });

  return router;
}
