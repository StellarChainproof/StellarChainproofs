import { SimulatedCompilerAdapter, getCompilerAdapter } from "../adapter";
import { verifyCompilerBinary, computeSha256 } from "../checksums";
import { validateCompilerCache, sanitizeCompilerOutput } from "../sandbox";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

describe("Compiler Adapter & Sandboxed Execution", () => {
  const adapter = new SimulatedCompilerAdapter();

  describe("Simulated Compiler compilation", () => {
    it("compiles contract, builds normalized ABI and calculates 4-byte selectors", async () => {
      const source = `
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.28;

        contract Token {
            mapping(address => uint256) public balanceOf;
            event Transfer(address indexed from, address indexed to, uint256 value);

            function transfer(address to, uint256 amount) external returns (bool) {
                balanceOf[to] += amount;
                emit Transfer(msg.sender, to, amount);
                return true;
            }
        }
      `;

      const result = await adapter.compile(
        [{ file: "Token.sol", content: source }],
        { optimizer: { enabled: true, runs: 200 } },
        "0.8.28",
      );

      expect(result.success).toBe(true);
      expect(result.contracts["Token"]).toBeDefined();

      const tokenArtifact = result.contracts["Token"];
      expect(tokenArtifact.abi.length).toBeGreaterThanOrEqual(2);

      const transferEntry = tokenArtifact.abi.find((e) => e.name === "transfer");
      expect(transferEntry).toBeDefined();
      expect(transferEntry?.selector).toBe("0xa9059cbb");

      const transferEvent = tokenArtifact.abi.find((e) => e.name === "Transfer");
      expect(transferEvent).toBeDefined();
      expect(transferEvent?.selector).toBe(
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
      );
    });

    it("calculates storage layout slots and packing properly", async () => {
      const source = `
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.28;

        contract PackedStorage {
            address public owner;     // slot 0, offset 0 (20 bytes)
            uint96 public nonce;      // slot 0, offset 20 (12 bytes) -> PACKED into slot 0!
            uint256 public balance;   // slot 1, offset 0 (32 bytes)
        }
      `;

      const result = await adapter.compile(
        [{ file: "PackedStorage.sol", content: source }],
        {},
        "0.8.28",
      );

      const artifact = result.contracts["PackedStorage"];
      expect(artifact).toBeDefined();

      const storage = artifact.storageLayout.storage;
      expect(storage.length).toBe(3);

      const ownerVar = storage.find((s) => s.label === "owner");
      const nonceVar = storage.find((s) => s.label === "nonce");
      const balanceVar = storage.find((s) => s.label === "balance");

      expect(ownerVar?.slot).toBe(0);
      expect(ownerVar?.offset).toBe(0);

      expect(nonceVar?.slot).toBe(0);
      expect(nonceVar?.offset).toBe(20);

      expect(balanceVar?.slot).toBe(1);
      expect(balanceVar?.offset).toBe(0);

      expect(artifact.storageLayout.hasPacking).toBe(true);
      expect(artifact.storageLayout.totalSlots).toBe(2);
    });

    it("emits PUSH0 opcode for 0.8.20+ with Shanghai EVM target", async () => {
      const source = `
        pragma solidity 0.8.20;
        contract Push0Contract {
            function foo() external {}
        }
      `;

      const resultShanghai = await adapter.compile(
        [{ file: "Push0Contract.sol", content: source }],
        { evmVersion: "shanghai" },
        "0.8.20",
      );
      expect(resultShanghai.contracts["Push0Contract"].bytecode.hasPush0).toBe(true);

      const resultParis = await adapter.compile(
        [{ file: "Push0Contract.sol", content: source }],
        { evmVersion: "paris" },
        "0.8.20",
      );
      expect(resultParis.contracts["Push0Contract"].bytecode.hasPush0).toBe(false);
    });
  });

  describe("Binary verification & Checksums", () => {
    it("computes SHA-256 and verifies binary", () => {
      const tempFile = path.join(os.tmpdir(), "test_compiler_bin");
      const content = "simulated_compiler_binary_content";
      fs.writeFileSync(tempFile, content);

      const expectedSha256 = computeSha256(content);
      const res = verifyCompilerBinary(tempFile, { expectedSha256 });
      expect(res.valid).toBe(true);
      expect(res.computedSha256).toBe(expectedSha256);

      fs.unlinkSync(tempFile);
    });
  });

  describe("Sandbox & Error Sanitization", () => {
    it("scrubs user home directories and API keys from error output", () => {
      const rawError =
        "Error in /home/nanle/secret/Vault.sol: invalid token sk-ant-api03-abcdef123456789012345678";
      const sanitized = sanitizeCompilerOutput(rawError);
      expect(sanitized).not.toContain("/home/nanle");
      expect(sanitized).toContain("<sanitized-home>");
      expect(sanitized).not.toContain("sk-ant-api03-abcdef123456789012345678");
      expect(sanitized).toContain("[REDACTED_API_KEY]");
    });

    it("validates and cleans corrupt compiler cache directories", () => {
      const tempCacheDir = path.join(os.tmpdir(), "test_compiler_cache_" + Date.now());
      fs.mkdirSync(tempCacheDir);

      const validJson = path.join(tempCacheDir, "valid.json");
      fs.writeFileSync(validJson, JSON.stringify({ version: "0.8.28" }));

      const corruptJson = path.join(tempCacheDir, "corrupt.json");
      fs.writeFileSync(corruptJson, "{ invalid json corrupt");

      const report = validateCompilerCache(tempCacheDir, true);
      expect(report.totalFiles).toBe(2);
      expect(report.validFiles).toBe(1);
      expect(report.corruptFiles.length).toBe(1);
      expect(report.cleanedFiles.length).toBe(1);

      fs.rmSync(tempCacheDir, { recursive: true, force: true });
    });
  });
});
