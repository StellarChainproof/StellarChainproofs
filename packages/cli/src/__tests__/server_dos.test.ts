import * as http from "http";
import { createApp } from "@chainproof/server";

describe("Server /dos Routes", () => {
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

  it("POST /dos/inspect-loops inspects loop bounds", async () => {
    const res = await postJson("/dos/inspect-loops", {
      files: [
        {
          file: "Vault.sol",
          content: "pragma solidity 0.8.20;\ncontract Vault { address[] u; function f() public { for(uint i=0; i<u.length; i++){} } }",
        },
      ],
    });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data.length).toBe(1);
    expect(res.data[0].boundType).toBe("storage_array_bounded");
  });

  it("POST /dos/fanout inspects call fanout", async () => {
    const res = await postJson("/dos/fanout", {
      files: [
        {
          file: "Vault.sol",
          content: "pragma solidity 0.8.20;\ncontract Vault { address[] u; function f() public { for(uint i=0; i<u.length; i++){ payable(u[i]).transfer(1); } } }",
        },
      ],
    });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data.length).toBe(1);
    expect(res.data[0].isPushPayment).toBe(true);
  });

  it("POST /dos/audit runs full audit", async () => {
    const res = await postJson("/dos/audit", {
      files: [
        {
          file: "Vault.sol",
          content: "pragma solidity 0.8.20;\ncontract Vault { address[] u; function f() public { for(uint i=0; i<u.length; i++){ payable(u[i]).transfer(1); } } }",
        },
      ],
    });

    expect(res.status).toBe(200);
    expect(res.data.schemaVersion).toBe("1.0.0");
    expect(res.data.summary.unboundedLoopsFound).toBe(1);
    expect(res.data.summary.passed).toBe(false);
  });

  it("POST /dos/audit returns 400 for invalid payload", async () => {
    const res = await postJson("/dos/audit", {
      files: "invalid-not-array",
    });

    expect(res.status).toBe(400);
    expect(res.data.error).toBeDefined();
  });
});
