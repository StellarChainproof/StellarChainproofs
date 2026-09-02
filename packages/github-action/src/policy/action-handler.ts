import { PolicyRunner, ScanFinding } from '@chainproof/cli/src/policy/policy-runner';
import { MarkdownReporter } from '@chainproof/cli/src/policy/markdown-reporter';

export interface ActionInputs {
  policyFiles: string[];
  rawFindings: ScanFinding[];
  baselineFindingsCount: number;
}

export class GitHubActionHandler {
  /**
   * Orchestrates the GitHub Action workflow for Policy Enforcement.
   * Designed to be easily wrapped by @actions/core without tightly coupling
   * the business logic to the GitHub environment.
   */
  public static async execute(inputs: ActionInputs): Promise<{ exitCode: number; summaryMarkdown: string }> {
    try {
      if (!inputs.policyFiles || inputs.policyFiles.length === 0) {
        throw new Error("No policy files provided to the action.");
      }

      const effectivePolicy = PolicyRunner.loadAndResolvePolicies(inputs.policyFiles);

      const result = PolicyRunner.enforce(effectivePolicy, inputs.rawFindings, inputs.baselineFindingsCount);

      const summaryMarkdown = MarkdownReporter.generateCiReport(result);

      const exitCode = result.passed ? 0 : 1;

      return {
        exitCode,
        summaryMarkdown
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown fatal error';
      return {
        exitCode: 1,
        summaryMarkdown: `## ❌ Security Policy Enforcement: CRITICAL ERROR\n\n**System Failure:** ${errorMessage}\n\n*Review your policy configurations.*`
      };
    }
  }
}
