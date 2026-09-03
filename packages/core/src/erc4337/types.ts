export type ERC4337Version = "0.6" | "0.7" | "0.8";

export type ERC4337Component =
  | "account"
  | "entryPoint"
  | "factory"
  | "aggregator"
  | "paymaster"
  | "module"
  | "fallback";

export type ERC4337DiagnosticCode =
  | "AA001_HASH_BINDING"
  | "AA002_ENTRYPOINT_DOMAIN"
  | "AA003_NONCE_REPLAY"
  | "AA004_VALIDATION_EXECUTION"
  | "AA005_AGGREGATOR_SIGNATURE"
  | "AA006_PAYMASTER_LIMIT"
  | "AA007_PAYMASTER_DEPOSIT"
  | "AA008_PAYMASTER_POSTOP"
  | "AA009_PAYMASTER_CONTEXT"
  | "AA010_FACTORY_INIT"
  | "AA011_CREATE2_DERIVATION"
  | "AA012_MODULE_AUTH"
  | "AA013_SESSION_KEY"
  | "AA014_UPGRADE_AUTH"
  | "AA015_FALLBACK_AUTH";

export interface UserOperationField {
  name: string;
  type: string;
  required: boolean;
  hashBound: boolean;
  sourceLine?: number;
}

export interface UserOperationModel {
  version: ERC4337Version;
  fields: UserOperationField[];
  hasPaymaster: boolean;
  hasFactory: boolean;
  hasAggregator: boolean;
  hashFunctions: string[];
  nonceFunctions: string[];
}

export interface ValidationDataModel {
  hasAuthorizer: boolean;
  hasTimeRange: boolean;
  usesPackedEncoding: boolean;
  rejectsInvalidAuthorizer: boolean;
  sourceLine?: number;
}

export interface NonceModel {
  hasNonceStorage: boolean;
  usesKeyedNonce: boolean;
  incrementsBeforeExecution: boolean;
  validatesNonce: boolean;
  sourceLine?: number;
}

export interface EntryPointModel {
  version: ERC4337Version;
  functions: string[];
  bindsChainId: boolean;
  bindsEntryPoint: boolean;
  validatesSender: boolean;
  hasDepositAccounting: boolean;
  sourceLine?: number;
}

export interface PaymasterModel {
  hasValidation: boolean;
  hasPostOp: boolean;
  validatesGasLimits: boolean;
  validatesContext: boolean;
  tracksDeposit: boolean;
  hasSponsorshipLimit: boolean;
  externalContextCalls: boolean;
  sourceLine?: number;
}

export interface ERC4337AnalysisLimits {
  maxSourceLength: number;
  maxFunctions: number;
  maxDiagnostics: number;
  maxEvidenceItems: number;
}

export interface ERC4337AnalysisOptions {
  version?: ERC4337Version | "auto";
  limits?: Partial<ERC4337AnalysisLimits>;
  signal?: AbortSignal;
}

export interface ERC4337Evidence {
  path: string;
  description: string;
  line?: number;
}

export interface ERC4337Diagnostic {
  code: ERC4337DiagnosticCode;
  component: ERC4337Component;
  version: ERC4337Version;
  title: string;
  description: string;
  recommendation: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  file: string;
  line: number;
  lineEnd?: number;
  evidence: ERC4337Evidence[];
  assumptions: string[];
  confidence: "high" | "medium" | "low";
}

export interface ERC4337AnalysisResult {
  schemaVersion: "erc4337-analysis-1";
  protocol: "erc-4337";
  version: ERC4337Version;
  components: ERC4337Component[];
  userOperation?: UserOperationModel;
  validationData?: ValidationDataModel;
  nonce?: NonceModel;
  entryPoint?: EntryPointModel;
  paymaster?: PaymasterModel;
  diagnostics: ERC4337Diagnostic[];
  truncated: boolean;
}

export const DEFAULT_ERC4337_ANALYSIS_LIMITS: ERC4337AnalysisLimits = {
  maxSourceLength: 2_000_000,
  maxFunctions: 2_000,
  maxDiagnostics: 100,
  maxEvidenceItems: 8,
};

export const ERC4337_VERSION_ORDER: readonly ERC4337Version[] = ["0.6", "0.7", "0.8"];
