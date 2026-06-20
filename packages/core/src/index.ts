export { scan } from "./scanner";
export { generateMarkdownReport, generateJSONReport, generateTableReport } from "./report/generator";
export { isSlitherAvailable } from "./ast/slither";
export {
  buildImportGraph,
  buildMergedContractViews,
  hasImportDirectives,
  resolveImportPath,
  indexContracts,
} from "./ast/import-graph";
export type {
  ScanConfig,
  ScanResult,
  FileScanResult,
  Finding,
  GasHint,
  Severity,
} from "./types";
export type {
  ImportGraph,
  ParsedSolidityFile,
  ContractInfo,
  MergedMember,
  MergedContractView,
} from "./ast/import-graph";
