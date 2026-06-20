export { scan } from "./scanner";
export { generateMarkdownReport, generateJSONReport, generateTableReport } from "./report/generator";
export { isSlitherAvailable } from "./ast/slither";
export { enhanceFindingsWithLLM } from "./llm/enhancer";
export type {
  ScanConfig,
  ScanResult,
  FileScanResult,
  Finding,
  GasHint,
  Severity,
} from "./types";
