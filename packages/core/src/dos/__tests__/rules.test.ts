import { parseSolidity } from "../../ast/parser";
import { detectDosVulnerabilities } from "../rules";

describe("DoS Rules (CP-DOS-001 to CP-DOS-010)", () => {
  it("flags CP-DOS-001 on unbounded loop over dynamic storage array", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Vault {
        address[] public holders;
        function run() public {
          for (uint256 i = 0; i < holders.length; i++) {}
        }
      }
    `;
    const { ast } = parseSolidity(source, "Vault.sol");
    const findings = detectDosVulnerabilities(ast!, source, "Vault.sol");

    expect(findings.some((f) => f.id === "CP-DOS-001")).toBe(true);
  });

  it("flags CP-DOS-002 on push payment inside loop", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Dividend {
        address[] public users;
        function pay() public payable {
          for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
          }
        }
      }
    `;
    const { ast } = parseSolidity(source, "Dividend.sol");
    const findings = detectDosVulnerabilities(ast!, source, "Dividend.sol");

    expect(findings.some((f) => f.id === "CP-DOS-002")).toBe(true);
  });

  it("flags CP-DOS-004 on unchecked return data from low-level call", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Relayer {
        function callExt(address target, bytes calldata data) public {
          (bool ok, ) = target.call(data);
          require(ok);
        }
      }
    `;
    const { ast } = parseSolidity(source, "Relayer.sol");
    const findings = detectDosVulnerabilities(ast!, source, "Relayer.sol");

    expect(findings.some((f) => f.id === "CP-DOS-004")).toBe(true);
  });

  it("flags CP-DOS-005 on mass storage deletion inside loop", () => {
    const source = `
      pragma solidity 0.8.20;
      contract ResetList {
        uint256[] public list;
        function clear() public {
          for (uint256 i = 0; i < list.length; i++) {
            delete list[i];
          }
        }
      }
    `;
    const { ast } = parseSolidity(source, "ResetList.sol");
    const findings = detectDosVulnerabilities(ast!, source, "ResetList.sol");

    expect(findings.some((f) => f.id === "CP-DOS-005")).toBe(true);
  });

  it("flags CP-DOS-008 on unbounded recursion", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Recursion {
        function countdown(uint256 n) public returns (uint256) {
          if (n == 0) return 0;
          return countdown(n - 1);
        }
      }
    `;
    const { ast } = parseSolidity(source, "Recursion.sol");
    const findings = detectDosVulnerabilities(ast!, source, "Recursion.sol");

    expect(findings.some((f) => f.id === "CP-DOS-008")).toBe(true);
  });

  it("flags CP-DOS-009 on unrestricted array growth", () => {
    const source = `
      pragma solidity 0.8.20;
      contract StorageAttack {
        address[] public spam;
        function pushEntry(address e) external {
          spam.push(e);
        }
        function flush() external {
          for (uint256 i = 0; i < spam.length; i++) {}
        }
      }
    `;
    const { ast } = parseSolidity(source, "StorageAttack.sol");
    const findings = detectDosVulnerabilities(ast!, source, "StorageAttack.sol");

    expect(findings.some((f) => f.id === "CP-DOS-009")).toBe(true);
  });

  it("does not flag CP-DOS-001 when pagination is used", () => {
    const source = `
      pragma solidity 0.8.20;
      contract SafeVault {
        address[] public holders;
        function getBatch(uint256 offset, uint256 limit) external view {
          uint256 end = offset + limit;
          for (uint256 i = offset; i < end; i++) {}
        }
      }
    `;
    const { ast } = parseSolidity(source, "SafeVault.sol");
    const findings = detectDosVulnerabilities(ast!, source, "SafeVault.sol");

    expect(findings.some((f) => f.id === "CP-DOS-001")).toBe(false);
  });
});
