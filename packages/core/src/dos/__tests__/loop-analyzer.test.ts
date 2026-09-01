import { parseSolidity } from "../../ast/parser";
import { extractLoopBounds } from "../loop-analyzer";

describe("DoS Loop Analyzer", () => {
  it("detects dynamic storage array loop bounds", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Vault {
        address[] public holders;
        function run() public {
          for (uint256 i = 0; i < holders.length; i++) {
            // do something
          }
        }
      }
    `;
    const { ast } = parseSolidity(source, "Vault.sol");
    const contract = ast!.children[1];
    const loops = extractLoopBounds(contract, "Vault", source, "Vault.sol");

    expect(loops.length).toBe(1);
    expect(loops[0].loopType).toBe("for");
    expect(loops[0].boundType).toBe("storage_array_bounded");
    expect(loops[0].targetVariable).toBe("holders");
    expect(loops[0].isCapped).toBe(false);
  });

  it("detects parameter-bounded loops with require upper-bound caps", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Batcher {
        function execute(uint256 count) public {
          require(count <= 50, "too high");
          for (uint256 i = 0; i < count; i++) {
            // do something
          }
        }
      }
    `;
    const { ast } = parseSolidity(source, "Batcher.sol");
    const contract = ast!.children[1];
    const loops = extractLoopBounds(contract, "Batcher", source, "Batcher.sol");

    expect(loops.length).toBe(1);
    expect(loops[0].boundType).toBe("parameter_bounded");
    expect(loops[0].isCapped).toBe(true);
    expect(loops[0].maxIterationsEstimate).toBe(50);
  });

  it("detects constant bounded loops", () => {
    const source = `
      pragma solidity 0.8.20;
      contract FixedLoop {
        uint256 constant MAX = 10;
        function run() public {
          for (uint256 i = 0; i < 10; i++) {}
          for (uint256 j = 0; j < MAX; j++) {}
        }
      }
    `;
    const { ast } = parseSolidity(source, "FixedLoop.sol");
    const contract = ast!.children[1];
    const loops = extractLoopBounds(contract, "FixedLoop", source, "FixedLoop.sol");

    expect(loops.length).toBe(2);
    expect(loops[0].boundType).toBe("constant_bounded");
    expect(loops[0].isCapped).toBe(true);
    expect(loops[0].maxIterationsEstimate).toBe(10);
    expect(loops[1].boundType).toBe("constant_bounded");
    expect(loops[1].isCapped).toBe(true);
  });

  it("detects operations inside loop bodies (calls, deletions, writes)", () => {
    const source = `
      pragma solidity 0.8.20;
      contract ComplexLoop {
        address[] public users;
        function clearAndPay() public {
          for (uint256 i = 0; i < users.length; i++) {
            delete users[i];
            payable(users[i]).transfer(1 ether);
          }
        }
      }
    `;
    const { ast } = parseSolidity(source, "ComplexLoop.sol");
    const contract = ast!.children[1];
    const loops = extractLoopBounds(contract, "ComplexLoop", source, "ComplexLoop.sol");

    expect(loops.length).toBe(1);
    expect(loops[0].hasExternalCalls).toBe(true);
    expect(loops[0].hasStorageDeletions).toBe(true);
    expect(loops[0].hasStateWrites).toBe(true);
  });
});
