import * as http from "http";
import { AddressInfo } from "net";
import { ApiKeyManager } from "@chainproof/core";
import { startServer, ServerInstance } from "../server";

describe("REST Server Hardening Integration Tests", () => {
  let serverInstance: ServerInstance;
  let baseUrl: string;
  let apiKeyManager: ApiKeyManager;
  let adminRawKey: string;
  let operatorRawKey: string;

  beforeAll(async () => {
    apiKeyManager = new ApiKeyManager();

    const admin = apiKeyManager.createApiKey({
      tenantId: "acme-corp",
      name: "Admin Key",
      roles: ["admin"],
      scopes: [
        "scan:create",
        "scan:read",
        "scan:cancel",
        "scan:delete",
        "jobs:manage",
        "metrics:read",
        "audit:read",
        "keys:manage",
      ],
    });
    adminRawKey = admin.rawKey;

    const operator = apiKeyManager.createApiKey({
      tenantId: "acme-corp",
      name: "Operator Key",
      roles: ["operator"],
      scopes: ["scan:create", "scan:read", "scan:cancel"],
    });
    operatorRawKey = operator.rawKey;

    serverInstance = await startServer({
      port: 0,
      host: "127.0.0.1",
      enableMultiTenant: true,
      apiKeyManager,
    });

    const addr = serverInstance.server?.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(async () => {
    if (serverInstance) {
      await serverInstance.close();
    }
  });

  function makeRequest(
    method: string,
    path: string,
    apiKey?: string,
    body?: Record<string, unknown>
  ): Promise<{ status: number; body: any }> {
    return new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      const payload = body ? JSON.stringify(body) : undefined;

      const headers: Record<string, string> = {};
      if (payload) {
        headers["Content-Type"] = "application/json";
        headers["Content-Length"] = String(Buffer.byteLength(payload));
      }

      if (apiKey) {
        headers["X-API-Key"] = apiKey;
      }

      const req = http.request(
        url,
        {
          method,
          headers,
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            try {
              resolve({
                status: res.statusCode ?? 500,
                body: data ? JSON.parse(data) : {},
              });
            } catch {
              resolve({
                status: res.statusCode ?? 500,
                body: data,
              });
            }
          });
        }
      );

      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  describe("Authentication & Authorization", () => {
    it("should reject unauthenticated access to protected endpoints", async () => {
      const res = await makeRequest("GET", "/jobs");
      expect(res.status).toBe(401);
      expect(res.body.error).toContain("Unauthorized");
    });

    it("should allow public health checks without auth", async () => {
      const res = await makeRequest("GET", "/health/ready");
      expect(res.status).toBe(200);
      expect(res.body.status).toBe("ready");
    });

    it("should allow access with valid API key", async () => {
      const res = await makeRequest("GET", "/jobs", operatorRawKey);
      expect(res.status).toBe(200);
      expect(res.body.jobs).toBeDefined();
    });
  });

  describe("Job Queue Lifecycle", () => {
    it("should submit, process, and query a scan job", async () => {
      const submitRes = await makeRequest("POST", "/jobs", operatorRawKey, {
        files: [
          {
            path: "contracts/Simple.sol",
            content: "pragma solidity ^0.8.0; contract Simple { uint256 public x; }",
          },
        ],
      });

      expect(submitRes.status).toBe(202);
      expect(submitRes.body.jobId).toBeDefined();

      const jobId = submitRes.body.jobId;

      // Poll until completed
      let status = "queued";
      let retries = 20;
      let jobResult: any;

      while ((status === "queued" || status === "running") && retries > 0) {
        await new Promise((r) => setTimeout(r, 200));
        const checkRes = await makeRequest("GET", `/jobs/${jobId}`, operatorRawKey);
        status = checkRes.body.status;
        jobResult = checkRes.body;
        retries--;
      }

      expect(status).toBe("completed");
      expect(jobResult.result).toBeDefined();
      expect(jobResult.result.files.length).toBe(1);
    });

    it("should cancel a queued/running job", async () => {
      const submitRes = await makeRequest("POST", "/jobs", operatorRawKey, {
        files: [
          {
            path: "contracts/Long.sol",
            content: "pragma solidity ^0.8.0; contract Long {}",
          },
        ],
      });

      const jobId = submitRes.body.jobId;

      const cancelRes = await makeRequest("POST", `/jobs/${jobId}/cancel`, operatorRawKey);
      expect(cancelRes.status).toBe(200);
      expect(cancelRes.body.job.status).toBe("cancelled");
    });
  });

  describe("API Key Management Routes", () => {
    it("should create, rotate, and list API keys", async () => {
      const createRes = await makeRequest("POST", "/auth/keys", adminRawKey, {
        name: "Dev Key",
        roles: ["operator"],
      });

      expect(createRes.status).toBe(201);
      expect(createRes.body.rawKey).toBeDefined();

      const createdKeyId = createRes.body.key.id;

      const listRes = await makeRequest("GET", "/auth/keys", adminRawKey);
      expect(listRes.status).toBe(200);
      expect(listRes.body.keys.length).toBeGreaterThan(0);

      const rotateRes = await makeRequest("POST", "/auth/keys/rotate", adminRawKey, {
        keyId: createdKeyId,
      });

      expect(rotateRes.status).toBe(200);
      expect(rotateRes.body.newRawKey).toBeDefined();
    });
  });

  describe("Metrics and Audit Logs", () => {
    it("should expose metrics and queryable audit logs", async () => {
      const metricsRes = await makeRequest("GET", "/metrics", adminRawKey);
      expect(metricsRes.status).toBe(200);
      expect(metricsRes.body.queue).toBeDefined();
      expect(metricsRes.body.quota).toBeDefined();

      const auditRes = await makeRequest("GET", "/audit", adminRawKey);
      expect(auditRes.status).toBe(200);
      expect(auditRes.body.events.length).toBeGreaterThan(0);
    });
  });
});
