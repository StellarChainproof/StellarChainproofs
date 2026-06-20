import "dotenv/config";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";

import healthRouter from "./routes/health";
import scanRouter from "./routes/scan";
import rulesRouter from "./routes/rules";

// ─── Configuration (can be overridden by env vars or programmatic start) ──────

export interface ServerOptions {
  port?: number;
  host?: string;
  /** Bearer token for auth. If empty, auth is disabled. */
  token?: string;
  /** Max concurrent scan requests in the rate-limit window. */
  maxRequests?: number;
  /** Max request body size (e.g. "5mb"). */
  bodySizeLimit?: string;
  /** Allow /scan/file endpoint (server filesystem access). */
  allowFs?: boolean;
}

// ─── Build the Express app ────────────────────────────────────────────────────

export function createApp(opts: ServerOptions = {}): express.Application {
  const app = express();

  // ── Request size limit ───────────────────────────────────────────────────
  const sizeLimit = opts.bodySizeLimit ?? process.env.CHAINPROOF_BODY_LIMIT ?? "5mb";
  app.use(express.json({ limit: sizeLimit }));
  app.use(cors());

  // ── Rate limiting ────────────────────────────────────────────────────────
  const maxRequests = opts.maxRequests ?? Number(process.env.CHAINPROOF_MAX_REQUESTS ?? 10);
  const limiter = rateLimit({
    windowMs: 60 * 1000, // 1-minute window
    max: maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: `Rate limit exceeded. Max ${maxRequests} requests per minute.`,
    },
  });
  app.use("/scan", limiter);

  // ── Optional bearer token auth ───────────────────────────────────────────
  const token = opts.token ?? process.env.CHAINPROOF_TOKEN ?? "";
  if (token) {
    app.use((req, res, next) => {
      // Health endpoint is public even when auth is on
      if (req.path === "/health") return next();

      const authHeader = req.headers["authorization"] ?? "";
      if (authHeader !== `Bearer ${token}`) {
        res.status(401).json({ error: "Unauthorized. Provide a valid Bearer token." });
        return;
      }
      next();
    });
  }

  // ── Propagate flags to routes via env ────────────────────────────────────
  if (opts.allowFs) {
    process.env.CHAINPROOF_ALLOW_FS = "true";
  }

  // ── Routes ───────────────────────────────────────────────────────────────
  app.use("/health", healthRouter);
  app.use("/scan", scanRouter);
  app.use("/rules", rulesRouter);

  // ── 404 handler ──────────────────────────────────────────────────────────
  app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  // ── Global error handler ─────────────────────────────────────────────────
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error("[ChainProof Server] Unhandled error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  });

  return app;
}

// ─── Standalone entry-point (called by CLI `chainproof serve`) ───────────────

export async function startServer(opts: ServerOptions = {}): Promise<void> {
  const port = opts.port ?? Number(process.env.PORT ?? 4243);
  const host = opts.host ?? process.env.HOST ?? "127.0.0.1";

  const app = createApp(opts);

  await new Promise<void>((resolve) => {
    app.listen(port, host, () => {
      console.log(`\n  🚀 ChainProof server running at http://${host}:${port}`);
      console.log(`  POST http://${host}:${port}/scan`);
      console.log(`  GET  http://${host}:${port}/health`);
      console.log(`  GET  http://${host}:${port}/rules`);
      if (opts.token) {
        console.log("  🔐 Bearer token authentication enabled");
      }
      if (opts.allowFs) {
        console.log("  📁 Filesystem access enabled (POST /scan/file)");
      }
      console.log();
      resolve();
    });
  });
}
