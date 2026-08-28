import { Router, Request, Response } from "express";
import { isSlitherAvailable, JobQueueManager, QueueWorker } from "@chainproof/core";

export interface HealthRouterOptions {
  queueManager?: JobQueueManager;
  worker?: QueueWorker;
}

export function createHealthRouter(options: HealthRouterOptions = {}): Router {
  const router = Router();

  const handleLiveness = (_req: Request, res: Response) => {
    res.json({
      status: "ok",
      version: "0.1.0",
      slitherAvailable: isSlitherAvailable(),
      timestamp: Date.now(),
    });
  };

  router.get("/", handleLiveness);
  router.get("/live", handleLiveness);

  router.get("/ready", (_req: Request, res: Response) => {
    const queueStats = options.queueManager ? options.queueManager.getStats() : undefined;
    const isReady = true;

    res.status(isReady ? 200 : 503).json({
      status: isReady ? "ready" : "not_ready",
      version: "0.1.0",
      slitherAvailable: isSlitherAvailable(),
      queue: queueStats,
      timestamp: Date.now(),
    });
  });

  return router;
}

export default createHealthRouter();
