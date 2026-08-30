import { parseSolidity } from "../../ast/parser";
import { extractCallFanOuts } from "../call-fanout";

describe("DoS Call Fan-Out Analyzer", () => {
  it("detects value transfer inside loop as push payment", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Fanout {
        address[] public recipients;
        function payAll() public {
          for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(100);
          }
        }
      }
    `;
    const { ast } = parseSolidity(source, "Fanout.sol");
    const contract = ast!.children[1];
    const calls = extractCallFanOuts(contract, "Fanout", source, "Fanout.sol");

    expect(calls.length).toBe(1);
    expect(calls[0].callType).toBe("value_transfer");
    expect(calls[0].isInsideLoop).toBe(true);
    expect(calls[0].isPushPayment).toBe(true);
  });

  it("detects low-level call without gas stipend", () => {
    const source = `
      pragma solidity 0.8.20;
      contract Relayer {
        function forward(address target, bytes calldata data) public {
          (bool ok, ) = target.call(data);
        }
      }
    `;
    const { ast } = parseSolidity(source, "Relayer.sol");
    const contract = ast!.children[1];
    const calls = extractCallFanOuts(contract, "Relayer", source, "Relayer.sol");

    expect(calls.length).toBe(1);
    expect(calls[0].callType).toBe("low_level_call");
    expect(calls[0].hasGasLimit).toBe(false);
    expect(calls[0].isWrappedInTryCatch).toBe(false);
  });

  it("detects try/catch wrapped high-level call", () => {
    const source = `
      pragma solidity 0.8.20;
      interface IFoo { function bar() external; }
      contract SafeCaller {
        function callSafe(address target) public {
          try IFoo(target).bar() {} catch {}
        }
      }
    `;
    const { ast } = parseSolidity(source, "SafeCaller.sol");
    const contract = ast!.children[2];
    const calls = extractCallFanOuts(contract, "SafeCaller", source, "SafeCaller.sol");

    expect(calls.length).toBe(1);
    expect(calls[0].isWrappedInTryCatch).toBe(true);
  });
});
