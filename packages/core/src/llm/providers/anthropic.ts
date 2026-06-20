import axios from "axios";
import type { Finding } from "../../types";
import type { EnhanceContext, LlmProvider, LlmProviderConfig } from "./types";

const ANTHROPIC_API = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL = "claude-sonnet-4-20250514";

function buildPrompt(finding: Finding, sourceCode: string): string {
  return `You are a senior smart contract security auditor. 
  
A vulnerability scanner found the following issue in a Solidity contract:

**Finding:** ${finding.title} (${finding.id})
**Severity:** ${finding.severity}
**Location:** Line ${finding.line}
**Snippet:**
\`\`\`solidity
${finding.snippet ?? "(no snippet)"}
\`\`\`

**Scanner description:** ${finding.description}

The full contract source (for context):
\`\`\`solidity
${sourceCode.slice(0, 3000)}
\`\`\`

Provide:
1. A concise, developer-friendly explanation of WHY this is dangerous in this specific contract
2. A concrete, copy-paste-ready fix for this exact code
3. A real-world exploit scenario (1–2 sentences)

Format your response as JSON with keys: "explanation", "fix", "exploitScenario"
Respond ONLY with the JSON object, no markdown fences.`;
}

export class AnthropicProvider implements LlmProvider {
  async enhanceFinding(
    finding: Finding,
    context: EnhanceContext,
    cfg: LlmProviderConfig
  ): Promise<Finding> {
    const apiKey = cfg.apiKey;
    if (!apiKey) return finding;

    const prompt = buildPrompt(finding, context.sourceCode);

    try {
      const response = await axios.post(
        ANTHROPIC_API,
        {
          model: cfg.model ?? DEFAULT_MODEL,
          max_tokens: 600,
          messages: [{ role: "user", content: prompt }],
        },
        {
          headers: {
            "x-api-key": apiKey,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
          },
          timeout: 30_000,
        }
      );

      const text = response.data?.content?.[0]?.text ?? "";
      const parsed = JSON.parse(text) as {
        explanation?: string;
        fix?: string;
        exploitScenario?: string;
      };

      return {
        ...finding,
        description: parsed.explanation ?? finding.description,
        recommendation: parsed.fix ?? finding.recommendation,
        snippet: finding.snippet
          ? `${finding.snippet}\n\n// Exploit scenario: ${parsed.exploitScenario ?? ""}`
          : finding.snippet,
        llmEnhanced: true,
      };
    } catch {
      return finding;
    }
  }
}

