import { Router, Request, Response } from "express";
import { isSlitherAvailable } from "@chainproof/core";

const router = Router();

/**
 * GET /health
 *
 * Liveness probe — returns server version and optional dependency status.
 */
router.get("/", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    version: "0.1.0",
    slitherAvailable: isSlitherAvailable(),
  });
});

export default router;
