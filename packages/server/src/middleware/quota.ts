import { Response, NextFunction } from "express";
import { JobQueueManager, QuotaManager, StructuredQuotaError } from "@chainproof/core";
import { AuthenticatedRequest } from "./auth";

export function createQuotaMiddleware(quotaManager: QuotaManager, queueManager: JobQueueManager) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.principal) {
      return next();
    }

    if (req.method !== "POST" || (!req.path.startsWith("/scan") && !req.path.startsWith("/jobs"))) {
      return next();
    }

    try {
      quotaManager.checkAndRecordJobSubmission(req.principal.tenantId, queueManager);
      next();
    } catch (err) {
      if (err instanceof StructuredQuotaError) {
        if (err.payload.retryAfterSeconds) {
          res.setHeader("Retry-After", String(err.payload.retryAfterSeconds));
        }
        res.status(err.payload.metric === "concurrency" ? 429 : err.payload.metric === "rate_limit" ? 429 : 413).json(err.payload);
        return;
      }
      next(err);
    }
  };
}
