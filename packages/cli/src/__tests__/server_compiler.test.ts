import * as http from "http";
import { createApp } from "@chainproof/server";

describe("Server /compiler Routes", () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll((done) => {
    const app = createApp();
    server = http.createServer(app);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as any;
      baseUrl = `http://127.0.0.1:${addr.port}`;
      done();
    });
  });

  afterAll((done) => {
    server.close(done);
  });

  async function postJson(endpoint: string, body: any): Promise<{ status: number; data: any }> {
    return new Promise((resolve, reject) => {
      const postData = JSON.stringify(body);
      const url = new URL(endpoint, baseUrl);
      const req = http.request(
        url,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(postData),
          },
        },
        (res) => {
          let raw = "";
          res.on("data", (chunk) => {
            raw += chunk;
          });
          res.on("end", () => {
            try {
              const data = JSON.parse(raw);
              resolve({ status: res.statusCode || 200, data });
            } catch (err) {
              resolve({ status: res.statusCode || 200, data: raw });
            }
          });
        },
      );
      req.on("error", reject);
      req.write(postData);
      req.end();
    });
  }

  it("POST /compiler/inspect inspects pragma directives", async () => {
    const res = await postJson("/compiler/inspect", {
      files: [
        {
          file: "Vault.sol",
          content: "pragma solidity 0.8.28;\ncontract Vault {}",
        },
      ],
    });

    expect(res.status).toBe(200);
    expect(res.data.totalFiles).toBe(1);
    expect(res.data.globalRange).toBe("=0.8.28");
    expect(res.data.unsatisfiable).toBe(false);
  });

  it("POST /compiler/matrix evaluates compiler matrix grid", async () => {
    const res = await postJson("/compiler/matrix", {
      files: [
        {
          file: "Vault.sol",
          content: "pragma solidity 0.8.28;\ncontract Vault {}",
        },
      ],
      versions: ["0.8.20", "0.8.28"],
    });

    expect(res.status).toBe(200);
    expect(res.data.targetVersions).toEqual(["0.8.20", "0.8.28"]);
    expect(res.data.rows.length).toBe(1);
  });

  it("POST /compiler/compare compares versions", async () => {
    const res = await postJson("/compiler/compare", {
      files: [
        {
          file: "Vault.sol",
          content: "pragma solidity 0.8.28;\ncontract Vault { uint256 a; }",
        },
      ],
      versions: ["0.8.20", "0.8.28"],
    });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data[0].contractName).toBe("Vault");
  });

  it("POST /compiler/audit performs full audit", async () => {
    const res = await postJson("/compiler/audit", {
      files: [
        {
          file: "Vault.sol",
          content: "pragma solidity 0.8.28;\ncontract Vault {}",
        },
      ],
    });

    expect(res.status).toBe(200);
    expect(res.data.schemaVersion).toBe("1.0.0");
    expect(res.data.summary.passed).toBe(true);
  });

  it("POST /compiler/inspect handles invalid payload with 400", async () => {
    const res = await postJson("/compiler/inspect", {
      files: "not-an-array",
    });

    expect(res.status).toBe(400);
    expect(res.data.error).toBeDefined();
  });
});
