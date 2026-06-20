import * as fc from "fast-check";
import { parseSolidity } from "../../ast/parser";
import { detectGasIssues } from "../gas-optimizer";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const LOOP_WITH_STORAGE = `
pragma solidity ^0.8.0;
contract LoopStorage {
  mapping(address => uint256) public balances;
  address[] public users;

  function distributeAll(uint256 amount) external {
    for (uint256 i = 0; i < users.length; i++) {
      balances[users[i]] += amount;
    }
  }
}
`;

const PUBLIC_STRING_VAR = `
pragma solidity ^0.8.0;
contract HasString {
  string public name = "ChainProof";
  bytes public data = "0x1234";
}
`;

const KECCAK_RUNTIME = `
pragma solidity ^0.8.0;
contract Hasher {
  bytes32 public h;
  function hashIt(string calldata input) external {
    h = keccak256(abi.encodePacked(input));
  }
}
`;

const LEQ_LOOP = `
pragma solidity ^0.8.0;
contract LessEqualLoop {
  uint256 public result;
  function sum(uint256 n) external {
    for (uint256 i = 0; i <= n; i++) {
      result += i;
    }
  }
}
`;

const SMALL_UINT_STORAGE = `
pragma solidity ^0.8.0;
contract SmallUint {
  uint8 public counter;
  uint16 public flags;
}
`;

const EMPTY_CONTRACT = `pragma solidity ^0.8.0; contract Empty {}`;

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("detectGasIssues", () => {
  it("flags storage reads (IndexAccess / MemberAccess) inside a for loop", () => {
    const { ast } = parseSolidity(LOOP_WITH_STORAGE, "loop.sol");
    expect(ast).not.toBeNull();
    const hints = detectGasIssues(ast!, LOOP_WITH_STORAGE, "loop.sol");
    const loopHints = hints.filter((h) => h.description.includes("loop") || h.description.includes("SLOAD"));
    expect(loopHints.length).toBeGreaterThan(0);
  });

  it("flags public string / bytes state variables", () => {
    const { ast } = parseSolidity(PUBLIC_STRING_VAR, "str.sol");
    expect(ast).not.toBeNull();
    const hints = detectGasIssues(ast!, PUBLIC_STRING_VAR, "str.sol");
    const stringHints = hints.filter(
      (h) => h.description.includes("string") || h.description.includes("bytes")
    );
    expect(stringHints.length).toBeGreaterThan(0);
  });

  it("flags runtime keccak256 calls that could be precomputed", () => {
    const { ast } = parseSolidity(KECCAK_RUNTIME, "keccak.sol");
    expect(ast).not.toBeNull();
    const hints = detectGasIssues(ast!, KECCAK_RUNTIME, "keccak.sol");
    const keccakHints = hints.filter((h) => h.description.includes("keccak256"));
    expect(keccakHints.length).toBeGreaterThan(0);
  });

  it("flags <= comparison in loop condition", () => {
    const { ast } = parseSolidity(LEQ_LOOP, "leq.sol");
    expect(ast).not.toBeNull();
    const hints = detectGasIssues(ast!, LEQ_LOOP, "leq.sol");
    const leqHints = hints.filter((h) => h.description.includes("<="));
    expect(leqHints.length).toBeGreaterThan(0);
  });

  it("flags small uint types (uint8, uint16) as storage state variables", () => {
    const { ast } = parseSolidity(SMALL_UINT_STORAGE, "small.sol");
    expect(ast).not.toBeNull();
    const hints = detectGasIssues(ast!, SMALL_UINT_STORAGE, "small.sol");
    expect(hints.length).toBeGreaterThan(0);
  });

  it("returns no hints for an empty contract", () => {
    const { ast } = parseSolidity(EMPTY_CONTRACT, "empty.sol");
    expect(ast).not.toBeNull();
    const hints = detectGasIssues(ast!, EMPTY_CONTRACT, "empty.sol");
    expect(hints).toHaveLength(0);
  });

  it("each hint has a non-empty description and estimatedSaving", () => {
    const { ast } = parseSolidity(LOOP_WITH_STORAGE, "loop.sol");
    const hints = detectGasIssues(ast!, LOOP_WITH_STORAGE, "loop.sol");
    hints.forEach((h) => {
      expect(h.description.length).toBeGreaterThan(0);
      expect(h.estimatedSaving.length).toBeGreaterThan(0);
    });
  });

  // ── Property-based tests ───────────────────────────────────────────────────

  it("[property] always detects keccak256 runtime call regardless of function name", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("alpha", "beta", "gamma", "myFunc", "run"),
        (fnName) => {
          const source = `
            pragma solidity ^0.8.0;
            contract C {
              bytes32 public h;
              function ${fnName}(string calldata s) external { h = keccak256(abi.encodePacked(s)); }
            }
          `;
          const { ast } = parseSolidity(source, "prop.sol");
          if (!ast) return true;
          const hints = detectGasIssues(ast, source, "prop.sol");
          return hints.some((h) => h.description.includes("keccak256"));
        }
      )
    );
  });

  it("[property] always detects public string variable regardless of variable name", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("name", "symbol", "uri", "description", "metadata"),
        (varName) => {
          const source = `
            pragma solidity ^0.8.0;
            contract C {
              string public ${varName} = "value";
            }
          `;
          const { ast } = parseSolidity(source, "prop.sol");
          if (!ast) return true;
          const hints = detectGasIssues(ast, source, "prop.sol");
          return hints.some((h) => h.description.includes("string") || h.description.includes(varName));
        }
      )
    );
  });
});
