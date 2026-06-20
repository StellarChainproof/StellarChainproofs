import type { Finding } from "../../types";

export interface EnhanceContext {
  sourceCode: string;
}

export interface LlmProviderConfig {
  /** Provider identifier (e.g. "anthropic", "openai") */
  provider: string;
  /** Model identifier (provider-specific) */
  model?: string;
  /** Provider API key (provider-specific) */
  apiKey?: string;
}

export interface LlmProvider {
  enhanceFinding(
    finding: Finding,
    context: EnhanceContext,
    cfg: LlmProviderConfig
  ): Promise<Finding>;
}

