export { scan } from "./scanner";
export { generateMarkdownReport, generateJSONReport, generateTableReport } from "./report/generator";
export { isSlitherAvailable } from "./ast/slither";
export { analyzeContract, computeFunctionComplexity, computeLinesOfCode, computeInheritanceDepth } from "./metrics/complexity";
export type {
  ScanConfig,
  ScanResult,
  FileScanResult,
  Finding,
  GasHint,
  Severity,
  ContractMetrics,
  HighComplexityFunction,
} from "./types";
