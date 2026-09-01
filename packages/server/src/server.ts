import "dotenv/config";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import * as http from "http";

import {
  ApiKeyManager,
  AuditLogger,
  DurableJobStore,
  JobQueueManager,
  OIDCConfig,
  OIDCVerifier,
  QueueWorker,
  QuotaManager,
} from "@chainproof/core";

import { createAuthMiddleware } from "./middleware/auth";
import { createQuotaMiddleware } from "./middleware/quota";
import { globalErrorHandler } from "./middleware/error-handler";

import { createHealthRouter } from "./routes/health";
import scanRouter from "./routes/scan";
import rulesRouter from "./routes/rules";
import { createJobsRouter } from "./routes/jobs";
import { createAuthRouter } from "./routes/auth";
import { createAuditRouter } from "./routes/audit";
import { createMetricsRouter } from "./routes/metrics";

export interface ServerOptions {
  port?: number;
  host?: string;
  token?: string;
  maxRequests?: number;
  bodySizeLimit?: string;
  allowFs?: boolean;

  // Multi-tenant & Durable Queue options
  enableMultiTenant?: boolean;
  storageDir?: string;
  workerConcurrency?: number;
  apiKeyManager?: ApiKeyManager;
  oidcConfig?: OIDCConfig;
  quotaManager?: QuotaManager;
  auditLogger?: AuditLogger;
  queueManager?: JobQueueManager;
  worker?: QueueWorker;
}

export interface ServerInstance {
  app: express.Application;
  server?: http.Server;
  queueManager: JobQueueManager;
  worker: QueueWorker;
  apiKeyManager: ApiKeyManager;
  quotaManager: QuotaManager;
  auditLogger: AuditLogger;
  close: () => Promise<void>;
}

export function createServerInstance(opts: ServerOptions = {}): ServerInstance {
  const app = express();

  const apiKeyManager = opts.apiKeyManager ?? new ApiKeyManager();
  const oidcVerifier = opts.oidcConfig ? new OIDCVerifier(opts.oidcConfig) : undefined;
  const auditLogger = opts.auditLogger ?? new AuditLogger();
  const quotaManager = opts.quotaManager ?? new QuotaManager();

  const jobStore = new DurableJobStore({ storageDir: opts.storageDir });
  const queueManager = opts.queueManager ?? new JobQueueManager({ store: jobStore });
  const worker =
    opts.worker ??
    new QueueWorker({
      queueManager,
      concurrency: opts.workerConcurrency ?? 2,
    });

  // Start queue worker
  worker.start();

  // Size limit & CORS
  const sizeLimit = opts.bodySizeLimit ?? process.env.CHAINPROOF_BODY_LIMIT ?? "50mb";
  app.use(express.json({ limit: sizeLimit }));
  app.use(cors());

  // Rate Limiting
  const maxRequests = opts.maxRequests ?? Number(process.env.CHAINPROOF_MAX_REQUESTS ?? 100);
  const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: `Rate limit exceeded. Max ${maxRequests} requests per minute.` },
  });
  app.use("/scan", limiter);
  app.use("/jobs", limiter);

  // Authentication Middleware
  const authMiddleware = createAuthMiddleware({
    apiKeyManager,
    oidcVerifier,
    bearerToken: opts.token ?? process.env.CHAINPROOF_TOKEN ?? "",
    enableMultiTenant: opts.enableMultiTenant ?? false,
  });
  app.use(authMiddleware);

  // Quota Middleware
  app.use(createQuotaMiddleware(quotaManager, queueManager));

  if (opts.allowFs) {
    process.env.CHAINPROOF_ALLOW_FS = "true";
  }

  // Routes
  app.use("/health", createHealthRouter({ queueManager, worker }));
  app.use("/scan", scanRouter);
  app.use("/jobs", createJobsRouter({ queueManager, worker, auditLogger }));
  app.use("/auth", createAuthRouter({ apiKeyManager, auditLogger }));
  app.use("/audit", createAuditRouter(auditLogger));
  app.use("/metrics", createMetricsRouter(queueManager, quotaManager));
  app.use("/rules", rulesRouter);
  app.use("/dos", dosRouter);

  // 404 handler
  app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  // Global error handler
  app.use(globalErrorHandler);

  const instance: ServerInstance = {
    app,
    queueManager,
    worker,
    apiKeyManager,
    quotaManager,
    auditLogger,
    close: async () => {
      worker.stop();
      if (instance.server) {
        await new Promise<void>((resolve) => {
          instance.server!.close(() => resolve());
        });
      }
    },
  };

  return instance;
}

export function createApp(opts: ServerOptions = {}): express.Application {
  const instance = createServerInstance(opts);
  return instance.app;
}

export async function startServer(opts: ServerOptions = {}): Promise<ServerInstance> {
  const port = opts.port ?? Number(process.env.PORT ?? 4243);
  const host = opts.host ?? process.env.HOST ?? "127.0.0.1";

  const instance = createServerInstance(opts);

  await new Promise<void>((resolve) => {
    const server = instance.app.listen(port, host, () => {
      instance.server = server;
      console.log(`\n  🚀 ChainProof REST Server running at http://${host}:${port}`);
      console.log(`  POST http://${host}:${port}/jobs       (Async durable priority queue)`);
      console.log(`  POST http://${host}:${port}/scan       (Synchronous scan)`);
      console.log(`  GET  http://${host}:${port}/health     (Health & Readiness probes)`);
      console.log(`  GET  http://${host}:${port}/metrics    (Metrics & Quota status)`);
      console.log(`  GET  http://${host}:${port}/audit      (Audit logs)`);
      console.log(`  POST http://${host}:${port}/auth/keys (API key management)`);
      console.log();
      resolve();
    });
  });

  return instance;
}
