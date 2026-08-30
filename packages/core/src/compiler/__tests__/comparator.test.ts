import {
  diffABI,
  diffStorageLayout,
  diffBytecode,
  diffDiagnostics,
  compareContractVersions,
} from "../comparator";
import { SimulatedCompilerAdapter } from "../adapter";

describe("Cross-Compiler Differential Comparison", () => {
  const adapter = new SimulatedCompilerAdapter();

  describe("diffABI", () => {
    it("detects added, removed, and mutated function signatures", () => {
      const baseArtifact: any = {
        abi: [
          { type: "function", name: "deposit", signature: "deposit(uint256)", stateMutability: "payable" },
          { type: "function", name: "oldMethod", signature: "oldMethod()", stateMutability: "nonpayable" },
        ],
      };

      const targetArtifact: any = {
        abi: [
          { type: "function", name: "deposit", signature: "deposit(uint256,bytes)", stateMutability: "payable" },
          { type: "function", name: "newMethod", signature: "newMethod()", stateMutability: "nonpayable" },
        ],
      };

      const diff = diffABI(baseArtifact, targetArtifact);
      expect(diff.identical).toBe(false);
      expect(diff.addedFunctions).toContain("newMethod()");
      expect(diff.removedFunctions).toContain("oldMethod()");
      expect(diff.mutatedSignatures.length).toBe(1);
      expect(diff.mutatedSignatures[0].name).toBe("deposit");
    });
  });

  describe("diffStorageLayout", () => {
    it("detects critical storage layout slot shifts (e.g. proxy upgrade hazard)", () => {
      const baseArtifact: any = {
        storageLayout: {
          storage: [
            { label: "owner", slot: 0, offset: 0, type: "address" },
            { label: "balance", slot: 1, offset: 0, type: "uint256" },
          ],
          layoutHash: "hash1",
        },
      };

      const targetArtifact: any = {
        storageLayout: {
          storage: [
            { label: "balance", slot: 0, offset: 0, type: "uint256" },
            { label: "owner", slot: 1, offset: 0, type: "address" },
          ],
          layoutHash: "hash2",
        },
      };

      const diff = diffStorageLayout(baseArtifact, targetArtifact);
      expect(diff.identical).toBe(false);
      expect(diff.slotCollisions.length).toBe(2);
      expect(diff.slotCollisions.some((c) => c.severity === "critical")).toBe(true);
      expect(diff.shiftedSlots.length).toBe(2);
    });
  });

  describe("compareContractVersions integration", () => {
    it("performs full differential comparison across compiler versions", async () => {
      const v1Source = `
        pragma solidity 0.8.20;
        contract Vault {
            address public owner;
            uint256 public total;
            function deposit(uint256 a) external {}
        }
      `;

      const v2Source = `
        pragma solidity 0.8.28;
        contract Vault {
            address public owner;
            uint256 public total;
            function deposit(uint256 a) external {}
            function withdraw(uint256 a) external {}
        }
      `;

      const resV1 = await adapter.compile([{ file: "Vault.sol", content: v1Source }], {}, "0.8.20");
      const resV2 = await adapter.compile([{ file: "Vault.sol", content: v2Source }], {}, "0.8.28");

      const comp = compareContractVersions("Vault", resV1, resV2);
      expect(comp.contractName).toBe("Vault");
      expect(comp.baseVersion).toBe("0.8.20");
      expect(comp.targetVersion).toBe("0.8.28");
      expect(comp.abiDiff.addedFunctions.length).toBe(1);
      expect(comp.storageLayoutDiff.identical).toBe(true);
    });
  });
});
