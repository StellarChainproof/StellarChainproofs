/**
 * @packageDocumentation
 * @chainproof/server — Denial-of-Service & Unbounded Work Routes
 */

import { Router, Request, Response } from "express";
import {
  auditDosSafety,
  inspectDosLoops,
  inspectDosCallFanOut,
  DosConfigError,
} from "@chainproof/core";
import type { DosSourceInput, DosAnalysisOptions } from "@chainproof/core";

const router = Router();

interface DosSourcePayload {
  path?: string;
  file?: string;
  content: string;
}

function normalizeSources(rawFiles: unknown): DosSourceInput[] {
  if (!Array.isArray(rawFiles) || rawFiles.length === 0) {
    throw new DosConfigError("Missing required field: files (array of { path/file, content })");
  }

  return rawFiles.map((f: DosSourcePayload, idx: number) => {
    const file = f.file || f.path || `Source_${idx + 1}.sol`;
    if (typeof f.content !== "string") {
      throw new DosConfigError(`File "${file}" missing valid string content.`);
    }
    return {
      file,
      content: f.content,
    };
  });
}

// ─── POST /dos/inspect-loops ──────────────────────────────────────────────────

router.post("/inspect-loops", (req: Request, res: Response): void => {
  try {
    const sources = normalizeSources(req.body?.files);
    const options: DosAnalysisOptions = {
      config: req.body?.config,
    };
    const loops = inspectDosLoops(sources, options);
    res.json(loops);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = err instanceof DosConfigError ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

// ─── POST /dos/fanout ─────────────────────────────────────────────────────────

router.post("/fanout", (req: Request, res: Response): void => {
  try {
    const sources = normalizeSources(req.body?.files);
    const options: DosAnalysisOptions = {
      config: req.body?.config,
    };
    const calls = inspectDosCallFanOut(sources, options);
    res.json(calls);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = err instanceof DosConfigError ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

// ─── POST /dos/audit ──────────────────────────────────────────────────────────

router.post("/audit", async (req: Request, res: Response): Promise<void> => {
  try {
    const sources = normalizeSources(req.body?.files);
    const options: DosAnalysisOptions = {
      includeRules: req.body?.includeRules,
      excludeRules: req.body?.excludeRules,
      minSeverity: req.body?.minSeverity,
      minConfidence: req.body?.minConfidence,
      config: req.body?.config,
    };
    const report = await auditDosSafety(sources, options);
    res.json(report);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = err instanceof DosConfigError ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

export default router;
