import type * as parser from "@solidity-parser/parser";

export type ASTNode = ReturnType<typeof parser.parse>;

export type ASTVisitor = Parameters<typeof parser.visit>[1];
