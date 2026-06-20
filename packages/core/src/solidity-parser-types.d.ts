import "@solidity-parser/parser";

declare module "@solidity-parser/parser" {
  export type ASTNode = import("@solidity-parser/parser/dist/src/ast-types").ASTNode;
  export type ASTVisitor = import("@solidity-parser/parser/dist/src/ast-types").ASTVisitor;
}
