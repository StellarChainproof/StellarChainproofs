# TODO — LLM provider abstraction (remove Anthropic lock-in)

- [ ] Implement LLM provider interface + Anthropic provider (default)
- [x] Refactor `packages/core/src/llm/enhancer.ts` to use provider instead of hardcoded Anthropic

- [x] Extend `packages/core/src/types.ts` (`ScanConfig`) to support `llmProvider` and `llmModel` (keep `apiKey` for backward compat)

- [x] Wire new config through `packages/core/src/scanner.ts`

- [ ] Update CLI (`packages/cli/src/cli.ts`) to add `--llm-provider` and `--llm-model` options and generalize env-var messaging
- [ ] Update VSCode extension (`packages/vscode-extension/src/extension.ts`) to read provider/model from settings and handle key selection for Anthropic vs others
- [ ] Build/typecheck across workspace
- [ ] Smoke test: run scan with default provider to ensure Anthropic still works

