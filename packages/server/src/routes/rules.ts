import { Router, Request, Response } from "express";
import { RULES } from "../rules-registry";

const router = Router();

/**
 * GET /rules
 *
 * Returns metadata for all registered ChainProof rules.
 * Useful for clients that want to display rule descriptions or filter findings.
 */
router.get("/", (_req: Request, res: Response) => {
  res.json({ rules: RULES, total: RULES.length });
});

export default router;
