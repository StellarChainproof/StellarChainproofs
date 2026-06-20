import type { LlmProvider, LlmProviderConfig } from "./types";
import { AnthropicProvider } from "./anthropic";

export function getLlmProvider(_cfg: Pick<LlmProviderConfig, "provider">): LlmProvider {
  switch ((_cfg.provider ?? "anthropic").toLowerCase()) {
    case "anthropic":
    default:
      return new AnthropicProvider();
  }
}

