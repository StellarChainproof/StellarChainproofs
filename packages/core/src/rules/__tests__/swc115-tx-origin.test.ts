import { parseSolidity } from "../../ast/parser";
import { detectTxOrigin } from "../swc115-tx-origin";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const VULNERABLE = `
pragma solidity ^0.8.0;
contract TxOriginAuth {
  address public owner;

  constructor() {
    owner = msg.sender;
  }

  function transferOwnership(address newOwner) external {
    require(tx.origin == owner, "Not owner");
    owner = newOwner;
  }
}
`;

// Uses msg.sender — correct pattern
const SECURE = `
pragma solidity ^0.8.0;
contract MsgSenderAuth {
  address public owner;

  constructor() {
    owner = msg.sender;
  }

  function transferOwnership(address newOwner) external {
    require(msg.sender == owner, "Not owner");
    owner = newOwner;
  }
}
`;

const EMPTY_CONTRACT = `pragma solidity ^0.8.0; contract Empty {}`;

const INTERFACE = `
pragma solidity ^0.8.0;
interface IOwnable {
  function transferOwnership(address newOwner) external;
}
`;

const ABSTRACT_CONTRACT = `
pragma solidity ^0.8.0;
abstract contract OwnableBase {
  function transferOwnership(address newOwner) external virtual;
}
`;

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("detectTxOrigin (SWC-115 / CP-115)", () => {
  it("flags tx.origin used for authorization", () => {
    const { ast } = parseSolidity(VULNERABLE, "vuln.sol");
    expect(ast).not.toBeNull();
    const findings = detectTxOrigin(ast!, VULNERABLE, "vuln.sol");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].id).toBe("CP-115");
    expect(findings[0].swcId).toBe("SWC-115");
    expect(findings[0].severity).toBe("high");
  });

  it("produces zero findings when msg.sender is used instead", () => {
    const { ast } = parseSolidity(SECURE, "secure.sol");
    expect(ast).not.toBeNull();
    const findings = detectTxOrigin(ast!, SECURE, "secure.sol");
    expect(findings).toHaveLength(0);
  });

  it("produces no false positives on an empty contract", () => {
    const { ast } = parseSolidity(EMPTY_CONTRACT, "empty.sol");
    expect(ast).not.toBeNull();
    const findings = detectTxOrigin(ast!, EMPTY_CONTRACT, "empty.sol");
    expect(findings).toHaveLength(0);
  });

  it("produces no false positives on an interface", () => {
    const { ast } = parseSolidity(INTERFACE, "iface.sol");
    expect(ast).not.toBeNull();
    const findings = detectTxOrigin(ast!, INTERFACE, "iface.sol");
    expect(findings).toHaveLength(0);
  });

  it("produces no false positives on an abstract contract with no body", () => {
    const { ast } = parseSolidity(ABSTRACT_CONTRACT, "abstract.sol");
    expect(ast).not.toBeNull();
    const findings = detectTxOrigin(ast!, ABSTRACT_CONTRACT, "abstract.sol");
    expect(findings).toHaveLength(0);
  });

  it("detects multiple tx.origin usages in the same contract", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract Multi {
        address public owner;
        function isOwner() internal view returns (bool) {
          return tx.origin == owner;
        }
        function transfer(address to) external {
          require(tx.origin == owner, "Not owner");
          owner = to;
        }
      }
    `;
    const { ast } = parseSolidity(source, "multi.sol");
    expect(ast).not.toBeNull();
    const findings = detectTxOrigin(ast!, source, "multi.sol");
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("includes file path and positive line number in each finding", () => {
    const { ast } = parseSolidity(VULNERABLE, "contracts/auth.sol");
    const findings = detectTxOrigin(ast!, VULNERABLE, "contracts/auth.sol");
    expect(findings[0].file).toBe("contracts/auth.sol");
    expect(findings[0].line).toBeGreaterThan(0);
  });
});
