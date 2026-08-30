/**
 * @packageDocumentation
 * @chainproof/core — Storage Growth & Array Poisoning Analyzer
 */

import { visit } from "../ast/parser";
import type { ArrayGrowthAnalysis } from "./types";

function extractExpressionString(node: any): string {
  if (!node) return "";
  if (node.type === "Identifier") return node.name || "";
  if (node.type === "NumberLiteral") return String(node.number || node.value || "");
  if (node.type === "MemberAccess") {
    return `${extractExpressionString(node.expression)}.${node.memberName}`;
  }
  if (node.type === "IndexAccess") {
    return `${extractExpressionString(node.base)}[${extractExpressionString(node.index)}]`;
  }
  if (node.type === "BinaryOperation") {
    return `${extractExpressionString(node.left)} ${node.operator} ${extractExpressionString(node.right)}`;
  }
  if (node.type === "UnaryOperation") {
    return node.isPrefix
      ? `${node.operator}${extractExpressionString(node.subExpression)}`
      : `${extractExpressionString(node.subExpression)}${node.operator}`;
  }
  if (node.type === "FunctionCall") {
    const callee = extractExpressionString(node.expression);
    const args = (node.arguments || []).map(extractExpressionString).join(", ");
    return `${callee}(${args})`;
  }
  return "";
}

export function extractArrayGrowths(
  contractNode: any,
  contractName: string,
  source: string,
  _filePath: string,
): ArrayGrowthAnalysis[] {
  if (!source.includes(".push")) {
    return [];
  }

  const dynamicArrays = new Map<string, string>(); // name -> type
  const arrayIteratingFunctions = new Map<string, Set<string>>(); // arrayName -> set of function names iterating it

  // 1. Identify dynamic storage arrays
  visit(contractNode, {
    StateVariableDeclaration: (decl: any) => {
      for (const v of decl.variables || []) {
        if (v.name) {
          const typeStr = v.typeName?.name || v.typeName?.namePath || "";
          if (v.typeName?.type === "ArrayTypeName" || typeStr.endsWith("[]")) {
            dynamicArrays.set(v.name, typeStr || "dynamic[]");
          }
        }
      }
    },
  });

  // 2. Identify iterating functions and growth operations in a single pass
  const rawGrowths: Array<{
    line: number;
    arrayName: string;
    isPublicOrExternal: boolean;
    hasAccessControl: boolean;
    hasRateLimitOrFee: boolean;
    hasLengthCap: boolean;
    associatedFunction: string;
    associatedContract: string;
  }> = [];

  visit(contractNode, {
    FunctionDefinition: (fnNode: any) => {
      const fnName = fnNode.name || (fnNode.isConstructor ? "constructor" : "fallback");
      const isPublicOrExternal =
        fnNode.visibility === "public" ||
        fnNode.visibility === "external" ||
        !fnNode.visibility;

      let hasAccessControl = false;
      let hasRateLimitOrFee = false;
      let hasLengthCap = false;

      // Check modifiers
      for (const mod of fnNode.modifiers || []) {
        const modName = (mod.name || "").toLowerCase();
        if (
          modName.includes("only") ||
          modName.includes("auth") ||
          modName.includes("admin") ||
          modName.includes("governor") ||
          modName.includes("owner")
        ) {
          hasAccessControl = true;
        }
      }

      visit(fnNode, {
        ForStatement: (forNode: any) => {
          checkIteration(forNode.conditionExpression || forNode.condition, fnName, dynamicArrays, arrayIteratingFunctions);
        },
        WhileStatement: (whileNode: any) => {
          checkIteration(whileNode.condition, fnName, dynamicArrays, arrayIteratingFunctions);
        },
        FunctionCall: (callNode: any) => {
          const callee = extractExpressionString(callNode.expression);
          if (callee === "require" && callNode.arguments?.length > 0) {
            const condStr = extractExpressionString(callNode.arguments[0]);
            if (condStr.includes("msg.sender") || condStr.includes("owner")) {
              hasAccessControl = true;
            }
            if (condStr.includes("msg.value")) {
              hasRateLimitOrFee = true;
            }
            if (condStr.includes(".length") && (condStr.includes("<") || condStr.includes("<="))) {
              hasLengthCap = true;
            }
          }
          if (callNode.expression?.type === "MemberAccess" && callNode.expression.memberName === "push") {
            const arrayName = extractExpressionString(callNode.expression.expression);
            if (dynamicArrays.has(arrayName)) {
              rawGrowths.push({
                line: callNode.loc?.start?.line || 1,
                arrayName,
                isPublicOrExternal,
                hasAccessControl,
                hasRateLimitOrFee,
                hasLengthCap,
                associatedFunction: fnName,
                associatedContract: contractName,
              });
            }
          }
        },
      });
    },
  });

  const growths: ArrayGrowthAnalysis[] = rawGrowths.map((g) => {
    const iteratingFns = Array.from(arrayIteratingFunctions.get(g.arrayName) || []);
    return {
      line: g.line,
      arrayName: g.arrayName,
      arrayType: dynamicArrays.get(g.arrayName) || "dynamic[]",
      pushExpression: `${g.arrayName}.push(...)`,
      isPublicOrExternal: g.isPublicOrExternal,
      hasAccessControl: g.hasAccessControl,
      hasRateLimitOrFee: g.hasRateLimitOrFee,
      hasLengthCap: g.hasLengthCap,
      associatedFunction: g.associatedFunction,
      associatedContract: g.associatedContract,
      isIteratedInContract: iteratingFns.length > 0,
      iteratingFunctions: iteratingFns,
    };
  });

  return growths;
}

function checkIteration(
  condNode: any,
  fnName: string,
  dynamicArrays: Map<string, string>,
  iteratingMap: Map<string, Set<string>>,
): void {
  if (!condNode) return;
  const condStr = extractExpressionString(condNode);
  for (const arrName of dynamicArrays.keys()) {
    if (condStr.includes(`${arrName}.length`)) {
      if (!iteratingMap.has(arrName)) {
        iteratingMap.set(arrName, new Set());
      }
      iteratingMap.get(arrName)!.add(fnName);
    }
  }
}
