import * as fc from "fast-check";
import { parseSolidity } from "../../ast/parser";
import { detectIntegerOverflow, detectUncheckedReturn } from "../swc101-overflow";
import { analyzeFunction, runSymbolicExec } from "../symbolic-exec";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const VULNERABLE_OVERFLOW = `
pragma solidity ^0.7.6;
contract Overflow {
  uint256 public count;
  function increment(uint256 x) external {
    count = count + x;
  }
}
`;

const SAFE_08 = `
pragma solidity ^0.8.0;
contract Safe {
  uint256 public count;
  function increment(uint256 x) external {
    count = count + x;
  }
}
`;

const SAFE_SAFEMATH = `
pragma solidity ^0.7.6;
import "@openzeppelin/contracts/math/SafeMath.sol";
contract SafeVault {
  using SafeMath for uint256;
  uint256 public count;
  function increment(uint256 x) external {
    count = count.add(x);
  }
}
`;

const UNCHECKED_CALL = `
pragma solidity ^0.8.0;
contract UncheckedSend {
  function pay(address payable recipient) external {
    recipient.call{value: 1 ether}("");
  }
}
`;

const CHECKED_CALL = `
pragma solidity ^0.8.0;
contract CheckedSend {
  function pay(address payable recipient) external {
    (bool ok, ) = recipient.call{value: 1 ether}("");
    require(ok, "failed");
  }
}
`;

// ─── False-positive fixture: manual bounds check (issue #2) ──────────────────
const MANUAL_BOUNDS_CHECK = `
pragma solidity ^0.7.6;
contract MathLib {
  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    require(a + b >= a, "overflow");
    return a + b;
  }
}
`;

// ─── False-negative fixture: unchecked block in >=0.8 (issue #2) ─────────────
const UNCHECKED_08_BLOCK = `
pragma solidity ^0.8.0;
contract Counter {
  uint256 public val;
  function dangerousDecrement(uint256 x) external {
    unchecked {
      x -= 1;
    }
    val = x;
  }
}
`;

// ─── Constrained range: provably safe addition ───────────────────────────────
const CONSTRAINED_SAFE = `
pragma solidity ^0.7.6;
contract Bounded {
  function add(uint256 a, uint256 b) external pure returns (uint256) {
    require(a <= 100);
    require(b <= 100);
    return a + b;
  }
}
`;

// ─── Unchecked block with constant operands (trivially safe) ─────────────────
const UNCHECKED_TRIVIAL_SAFE = `
pragma solidity ^0.8.0;
contract TrivialMath {
  function addSmall() external pure returns (uint256) {
    unchecked {
      uint256 result = 1 + 2;
      return result;
    }
  }
}
`;

// ─── Unchecked multiplication that can overflow ───────────────────────────────
const UNCHECKED_MUL_OVERFLOW = `
pragma solidity ^0.8.0;
contract UncheckedMul {
  function dangerous(uint256 a, uint256 b) external pure returns (uint256) {
    unchecked {
      return a * b;
    }
  }
}
`;

// ─── detectIntegerOverflow ────────────────────────────────────────────────────

describe("detectIntegerOverflow (SWC-101 / CP-101)", () => {
  it("flags arithmetic on pragma < 0.8.0 without SafeMath", () => {
    const { ast } = parseSolidity(VULNERABLE_OVERFLOW, "vuln.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, VULNERABLE_OVERFLOW, "vuln.sol");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].id).toBe("CP-101");
    expect(findings[0].severity).toBe("high");
  });

  it("produces no findings for pragma ^0.8.0 (overflow reverts natively)", () => {
    const { ast } = parseSolidity(SAFE_08, "safe.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, SAFE_08, "safe.sol");
    expect(findings.filter((f) => f.id === "CP-101")).toHaveLength(0);
  });

  it("produces no findings when SafeMath is in use (.add/.sub/.mul)", () => {
    const { ast } = parseSolidity(SAFE_SAFEMATH, "safemath.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, SAFE_SAFEMATH, "safemath.sol");
    expect(findings.filter((f) => f.id === "CP-101")).toHaveLength(0);
  });

  it("produces no false positives on an empty contract", () => {
    const source = `pragma solidity ^0.8.0; contract Empty {}`;
    const { ast } = parseSolidity(source, "empty.sol");
    const findings = detectIntegerOverflow(ast!, source, "empty.sol");
    expect(findings).toHaveLength(0);
  });

  // ── False-positive regression (issue #2) ──────────────────────────────────

  it("does NOT flag pre-0.8 manual bounds check require(a+b >= a)", () => {
    const { ast } = parseSolidity(MANUAL_BOUNDS_CHECK, "manual.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, MANUAL_BOUNDS_CHECK, "manual.sol");
    expect(findings.filter((f) => f.id === "CP-101")).toHaveLength(0);
  });

  it("does NOT flag pre-0.8 arithmetic when operands are provably bounded", () => {
    const { ast } = parseSolidity(CONSTRAINED_SAFE, "bounded.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, CONSTRAINED_SAFE, "bounded.sol");
    expect(findings.filter((f) => f.id === "CP-101")).toHaveLength(0);
  });

  // ── False-negative regression (issue #2) ──────────────────────────────────

  it("flags unchecked block subtraction in Solidity >=0.8", () => {
    const { ast } = parseSolidity(UNCHECKED_08_BLOCK, "unchecked08.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, UNCHECKED_08_BLOCK, "unchecked08.sol");
    const overflowFindings = findings.filter((f) => f.id === "CP-101");
    expect(overflowFindings.length).toBeGreaterThan(0);
    expect(overflowFindings[0].title).toContain("unchecked block");
  });

  it("flags unchecked multiplication in Solidity >=0.8", () => {
    const { ast } = parseSolidity(UNCHECKED_MUL_OVERFLOW, "uncheckedmul.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, UNCHECKED_MUL_OVERFLOW, "uncheckedmul.sol");
    expect(findings.filter((f) => f.id === "CP-101").length).toBeGreaterThan(0);
  });

  it("does NOT flag trivially safe constant arithmetic in unchecked block", () => {
    const { ast } = parseSolidity(UNCHECKED_TRIVIAL_SAFE, "trivial.sol");
    expect(ast).not.toBeNull();
    const findings = detectIntegerOverflow(ast!, UNCHECKED_TRIVIAL_SAFE, "trivial.sol");
    expect(findings.filter((f) => f.id === "CP-101")).toHaveLength(0);
  });

  // ── Property-based tests ───────────────────────────────────────────────────

  it("[property] never flags CP-101 on any 0.8.x or 0.9.x pragma (no unchecked)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("^0.8.0", "^0.8.20", ">=0.8.0", "0.8.17", "0.8.26", "0.9.0"),
        (version) => {
          const source = `
            pragma solidity ${version};
            contract C {
              uint256 x;
              function f(uint256 a, uint256 b) external { x = a + b; }
            }
          `;
          const { ast } = parseSolidity(source, "prop.sol");
          if (!ast) return true;
          const findings = detectIntegerOverflow(ast, source, "prop.sol");
          return findings.filter((f) => f.id === "CP-101").length === 0;
        }
      )
    );
  });

  it("[property] always flags CP-101 on pre-0.8 pragma with bare arithmetic", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("^0.7.0", "^0.6.0", "^0.5.0", "0.7.6", "0.6.12"),
        (version) => {
          const source = `
            pragma solidity ${version};
            contract C {
              uint256 x;
              function f(uint256 a) external { x = x + a; }
            }
          `;
          const { ast } = parseSolidity(source, "prop.sol");
          if (!ast) return true;
          const findings = detectIntegerOverflow(ast, source, "prop.sol");
          return findings.filter((f) => f.id === "CP-101").length > 0;
        }
      )
    );
  });

  it("[property] always flags CP-101 on unchecked arithmetic in >=0.8 with unbounded operands", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("+", "-", "*"),
        (operator) => {
          const source = `
            pragma solidity ^0.8.0;
            contract C {
              function f(uint256 a, uint256 b) external pure returns (uint256) {
                unchecked { return a ${operator} b; }
              }
            }
          `;
          const { ast } = parseSolidity(source, "prop.sol");
          if (!ast) return true;
          const findings = detectIntegerOverflow(ast, source, "prop.sol");
          return findings.filter((f) => f.id === "CP-101").length > 0;
        }
      )
    );
  });
});

// ─── detectUncheckedReturn ────────────────────────────────────────────────────

describe("detectUncheckedReturn (SWC-104 / CP-104)", () => {
  it("flags a bare .call() whose return value is not captured", () => {
    const { ast } = parseSolidity(UNCHECKED_CALL, "unchecked.sol");
    expect(ast).not.toBeNull();
    const findings = detectUncheckedReturn(ast!, UNCHECKED_CALL, "unchecked.sol");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].id).toBe("CP-104");
  });

  it("produces no findings when return value is captured and checked", () => {
    const { ast } = parseSolidity(CHECKED_CALL, "checked.sol");
    expect(ast).not.toBeNull();
    const findings = detectUncheckedReturn(ast!, CHECKED_CALL, "checked.sol");
    expect(findings).toHaveLength(0);
  });

  it("produces no false positives on an empty contract", () => {
    const source = `pragma solidity ^0.8.0; contract Empty {}`;
    const { ast } = parseSolidity(source, "empty.sol");
    const findings = detectUncheckedReturn(ast!, source, "empty.sol");
    expect(findings).toHaveLength(0);
  });
});

// ─── Symbolic execution engine unit tests ────────────────────────────────────

describe("analyzeFunction (symbolic-exec)", () => {
  it("returns no candidates for an empty body", () => {
    const result = analyzeFunction({ statements: [] }, { is08Plus: false });
    expect(result).toHaveLength(0);
  });

  it("guards out addition when require(a <= N) constrains hi below overflow", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract C {
        function f(uint256 a, uint256 b) external pure returns (uint256) {
          require(a <= 100);
          require(b <= 100);
          return a + b;
        }
      }
    `;
    const { ast } = parseSolidity(source, "c.sol");
    expect(ast).not.toBeNull();
    const candidates = runSymbolicExec(ast!, { is08Plus: false });
    expect(candidates.filter((c) => !c.guardedOut)).toHaveLength(0);
  });

  it("surfaces unguarded addition with unbounded operands", () => {
    const source = `
      pragma solidity ^0.7.6;
      contract C {
        function f(uint256 a, uint256 b) external pure returns (uint256) {
          return a + b;
        }
      }
    `;
    const { ast } = parseSolidity(source, "c.sol");
    expect(ast).not.toBeNull();
    const candidates = runSymbolicExec(ast!, { is08Plus: false });
    expect(candidates.length).toBeGreaterThan(0);
  });

  it("skips non-unchecked ops when is08Plus=true", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function f(uint256 a, uint256 b) external pure returns (uint256) {
          return a + b;
        }
      }
    `;
    const { ast } = parseSolidity(source, "c.sol");
    expect(ast).not.toBeNull();
    const candidates = runSymbolicExec(ast!, { is08Plus: true });
    expect(candidates).toHaveLength(0);
  });

  it("surfaces unchecked ops when is08Plus=true", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function f(uint256 a, uint256 b) external pure returns (uint256) {
          unchecked { return a + b; }
        }
      }
    `;
    const { ast } = parseSolidity(source, "c.sol");
    expect(ast).not.toBeNull();
    const candidates = runSymbolicExec(ast!, { is08Plus: true });
    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates.every((c) => c.inUncheckedBlock)).toBe(true);
  });
});
