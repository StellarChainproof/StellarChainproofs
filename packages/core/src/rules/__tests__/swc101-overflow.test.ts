import * as fc from "fast-check";
import { parseSolidity } from "../../ast/parser";
import { detectIntegerOverflow, detectUncheckedReturn } from "../swc101-overflow";

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

// Solidity ^0.8.0 has built-in overflow protection
const SAFE_08 = `
pragma solidity ^0.8.0;
contract Safe {
  uint256 public count;
  function increment(uint256 x) external {
    count = count + x;
  }
}
`;

// SafeMath usage on pre-0.8
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

  // ── Property-based tests ───────────────────────────────────────────────────

  it("[property] never flags CP-101 on any 0.8.x or 0.9.x pragma", () => {
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
