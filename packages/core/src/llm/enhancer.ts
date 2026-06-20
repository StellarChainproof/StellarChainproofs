import type { Finding, ScanConfig } from "../types";
import type { LlmProviderConfig } from "./providers/types";
import { getLlmProvider } from "./providers";

/**
 * Enhance findings with LLM-generated explanations and contextual recommendations.
 * Only enhances critical/high findings to keep latency reasonable.
 */
export async function enhanceFindingsWithLLM(
  findings: Finding[],
  sourceCode: string,
  config: ScanConfig
): Promise<Finding[]> {
  const toEnhance = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  );

  if (toEnhance.length === 0) return findings;

  const providerCfg: LlmProviderConfig = {
    provider: config.llmProvider ?? "anthropic",
    model: config.llmModel,
    apiKey: config.llmApiKey ?? config.apiKey,
  };

  if (!providerCfg.apiKey) return findings;

  const provider = getLlmProvider(providerCfg);

  const enhanced = await Promise.allSettled(
    toEnhance.map((finding) =>
      provider.enhanceFinding(finding, { sourceCode }, providerCfg)
    )
  );

  const enhancedMap = new Map<string, Finding>();
  enhanced.forEach((result, i) => {
    if (result.status === "fulfilled") {
      enhancedMap.set(toEnhance[i].id + toEnhance[i].line, result.value);
    }
  });

  return findings.map((f) => {
    const key = f.id + f.line;
    return enhancedMap.get(key) ?? f;
  });
}

