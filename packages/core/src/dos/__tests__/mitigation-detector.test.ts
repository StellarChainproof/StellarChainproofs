import { parseSolidity } from "../../ast/parser";
import { detectMitigations } from "../mitigation-detector";

describe("DoS Mitigation Detector", () => {
  it("recognizes pull payment pattern", () => {
    const source = `
      pragma solidity 0.8.20;
      contract PullVault {
        mapping(address => uint256) public pendingWithdrawals;
        function withdraw() external {
          uint256 amt = pendingWithdrawals[msg.sender];
          pendingWithdrawals[msg.sender] = 0;
          payable(msg.sender).transfer(amt);
        }
      }
    `;
    const { ast } = parseSolidity(source, "PullVault.sol");
    const contract = ast!.children[1];
    const mitigations = detectMitigations(contract, "PullVault", source, "PullVault.sol");

    expect(mitigations.some((m) => m.type === "pull_payment")).toBe(true);
  });

  it("recognizes pagination pattern", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Paginated {
        function getBatch(uint256 offset, uint256 limit) external view {}
      }
    `;
    const { ast } = parseSolidity(source, "Paginated.sol");
    const contract = ast!.children[1];
    const mitigations = detectMitigations(contract, "Paginated", source, "Paginated.sol");

    expect(mitigations.some((m) => m.type === "pagination")).toBe(true);
  });

  it("recognizes failure isolation with try/catch", () => {
    const source = `
      pragma solidity 0.8.20;
      interface ITarget { function doWork() external; }
      contract BatchIsolated {
        function run(address target) external {
          try ITarget(target).doWork() {} catch {}
        }
      }
    `;
    const { ast } = parseSolidity(source, "BatchIsolated.sol");
    const contract = ast!.children[2];
    const mitigations = detectMitigations(contract, "BatchIsolated", source, "BatchIsolated.sol");

    expect(mitigations.some((m) => m.type === "failure_isolation")).toBe(true);
  });
});
