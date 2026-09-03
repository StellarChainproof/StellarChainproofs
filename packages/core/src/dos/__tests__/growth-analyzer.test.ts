import { parseSolidity } from "../../ast/parser";
import { extractArrayGrowths } from "../growth-analyzer";

describe("DoS Storage Growth Analyzer", () => {
  it("detects unrestricted array growth on iterated storage array", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Queue {
        address[] public items;
        function addItem(address item) external {
          items.push(item);
        }
        function processAll() external {
          for (uint256 i = 0; i < items.length; i++) {}
        }
      }
    `;
    const { ast } = parseSolidity(source, "Queue.sol");
    const contract = ast!.children[1];
    const growths = extractArrayGrowths(contract, "Queue", source, "Queue.sol");

    expect(growths.length).toBe(1);
    expect(growths[0].arrayName).toBe("items");
    expect(growths[0].isPublicOrExternal).toBe(true);
    expect(growths[0].hasAccessControl).toBe(false);
    expect(growths[0].isIteratedInContract).toBe(true);
    expect(growths[0].iteratingFunctions).toContain("processAll");
  });

  it("recognizes access control and length caps", () => {
    const source = `
      pragma solidity 0.8.20;
      contract GuardedQueue {
        address[] public items;
        address public owner;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function addItem(address item) external onlyOwner {
          require(items.length < 100, "full");
          items.push(item);
        }
      }
    `;
    const { ast } = parseSolidity(source, "GuardedQueue.sol");
    const contract = ast!.children[1];
    const growths = extractArrayGrowths(contract, "GuardedQueue", source, "GuardedQueue.sol");

    expect(growths.length).toBe(1);
    expect(growths[0].hasAccessControl).toBe(true);
    expect(growths[0].hasLengthCap).toBe(true);
  });
});
