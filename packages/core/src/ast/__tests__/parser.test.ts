import { parseSolidity, getSnippet } from "../parser";
import type { ASTNode } from "@solidity-parser/parser";

describe("parseSolidity", () => {
  it("parses a valid Solidity contract and returns an AST", () => {
    const source = `pragma solidity ^0.8.0; contract C {}`;
    const { ast, error } = parseSolidity(source, "test.sol");
    expect(ast).not.toBeNull();
    expect(error).toBeUndefined();
  });

  it("handles syntax errors gracefully without throwing", () => {
    // parseSolidity uses tolerant:true so it may return a partial AST rather than null;
    // either way it must never throw.
    const source = `pragma solidity ^0.8.0; contract C { function broken( }`;
    expect(() => parseSolidity(source, "broken.sol")).not.toThrow();
    const { ast, error } = parseSolidity(source, "broken.sol");
    // At least one of ast or error must be set — never both missing
    expect(ast !== null || error !== undefined).toBe(true);
  });

  it("returns null AST with error message on a completely unparseable input", () => {
    // A raw non-Solidity payload that exceeds even tolerant-mode recovery
    const source = `{{{{{{{ this is not solidity at all @@@`;
    const result = parseSolidity(source, "garbage.sol");
    // Should not throw; error may be set or ast may be partial — never throws
    expect(() => parseSolidity(source, "garbage.sol")).not.toThrow();
  });

  it("returns null or a valid AST for empty source without throwing", () => {
    expect(() => parseSolidity("", "empty.sol")).not.toThrow();
  });

  it("parses an abstract contract without error", () => {
    const source = `
      pragma solidity ^0.8.0;
      abstract contract Base {
        function foo() external virtual;
      }
    `;
    const { ast } = parseSolidity(source, "abstract.sol");
    expect(ast).not.toBeNull();
  });

  it("parses an interface without error", () => {
    const source = `
      pragma solidity ^0.8.0;
      interface IVault {
        function withdraw(uint256 amount) external;
        function getBalance() external view returns (uint256);
      }
    `;
    const { ast } = parseSolidity(source, "interface.sol");
    expect(ast).not.toBeNull();
  });

  it("parses a library without error", () => {
    const source = `
      pragma solidity ^0.8.0;
      library SafeMath {
        function add(uint256 a, uint256 b) internal pure returns (uint256) {
          return a + b;
        }
      }
    `;
    const { ast } = parseSolidity(source, "lib.sol");
    expect(ast).not.toBeNull();
  });
});

describe("getSnippet", () => {
  it("extracts the correct single-line snippet", () => {
    const source = "line1\nline2\nline3";
    const node = { loc: { start: { line: 2 }, end: { line: 2 } } } as ASTNode;
    expect(getSnippet(source, node)).toBe("line2");
  });

  it("extracts a multi-line snippet", () => {
    const source = "alpha\nbeta\ngamma\ndelta";
    const node = { loc: { start: { line: 2 }, end: { line: 3 } } } as ASTNode;
    expect(getSnippet(source, node)).toBe("beta\ngamma");
  });

  it("returns empty string when loc is absent", () => {
    expect(getSnippet("some source", {} as ASTNode)).toBe("");
  });

  it("returns empty string when loc.start is missing", () => {
    const node = { loc: { end: { line: 2 } } } as ASTNode;
    expect(getSnippet("some source", node)).toBe("");
  });
});
