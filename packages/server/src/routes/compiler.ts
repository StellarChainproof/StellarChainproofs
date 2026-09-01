/**
 * @packageDocumentation
 * @chainproof/server — Compiler Matrix & Diagnostic Routes
 */

import { Router, Request, Response } from "express";
import {
  inspectCompilerPragmas,
  buildCompilerMatrix,
  compareCompilerVersions,
  auditCompilerCompatibility,
  CompilerConfigError,
} from "@chainproof/core";
import type { CompilerSourceInput, CompilerAnalysisOptions } from "@chainproof/core";

const router = Router();

interface CompilerSourcePayload {
  path?: string;
  file?: string;
  content: string;
}

function normalizeSources(rawFiles: unknown): CompilerSourceInput[] {
  if (!Array.isArray(rawFiles) || rawFiles.length === 0) {
    throw new CompilerConfigError("Missing required field: files (array of { path/file, content })");
  }

  return rawFiles.map((f: CompilerSourcePayload, idx: number) => {
    const file = f.file || f.path || `Source_${idx + 1}.sol`;
    if (typeof f.content !== "string") {
      throw new CompilerConfigError(`File "${file}" missing valid string content.`);
    }
    return {
      file,
      content: f.content,
    };
  });
}

// ─── POST /compiler/inspect ───────────────────────────────────────────────────

router.post("/inspect", (req: Request, res: Response): void => {
  try {
    const sources = normalizeSources(req.body?.files);
    const options: CompilerAnalysisOptions = {
      config: req.body?.config,
    };
    const result = inspectCompilerPragmas(sources, options);
    res.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = err instanceof CompilerConfigError ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

// ─── POST /compiler/matrix ────────────────────────────────────────────────────

router.post("/matrix", async (req: Request, res: Response): Promise<void> => {
  try {
    const sources = normalizeSources(req.body?.files);
    const options: CompilerAnalysisOptions = {
      targetVersions: req.body?.versions || req.body?.targetVersions,
      evmVersion: req.body?.evmVersion,
      optimizer: req.body?.optimizer,
      config: req.body?.config,
    };
    const grid = await buildCompilerMatrix(sources, options);
    res.json(grid);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = err instanceof CompilerConfigError ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

// ─── POST /compiler/compare ───────────────────────────────────────────────────

router.post("/compare", async (req: Request, res: Response): Promise<void> => {
  try {
    const sources = normalizeSources(req.body?.files);
    const versions = req.body?.versions as [string, string];
    if (!Array.isArray(versions) || versions.length !== 2) {
      res.status(400).json({ error: "Missing required field: versions (array of 2 version strings [base, target])" });
      return;
    }
    const options: CompilerAnalysisOptions = {
      evmVersion: req.body?.evmVersion,
      config: req.body?.config,
    };
    const comparisons = await compareCompilerVersions(sources, versions, options);
    res.json(comparisons);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = err instanceof CompilerConfigError ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

// ─── POST /compiler/audit ─────────────────────────────────────────────────────

router.post("/audit", async (req: Request, res: Response): Promise<void> => {
  try {
    const sources = normalizeSources(req.body?.files);
    const options: CompilerAnalysisOptions = {
      targetVersions: req.body?.versions || req.body?.targetVersions,
      compareVersions: req.body?.compareVersions,
      includeRules: req.body?.includeRules,
      excludeRules: req.body?.excludeRules,
      config: req.body?.config,
    };
    const report = await auditCompilerCompatibility(sources, options);
    res.json(report);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = err instanceof CompilerConfigError ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

export default router;
