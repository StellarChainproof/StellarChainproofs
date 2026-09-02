import { SecurityPolicy } from '@chainproof/core/src/policy-engine/schemas/policy.schema';

export enum DiagnosticSeverity {
  Error = 0,
  Warning = 1,
  Information = 2,
  Hint = 3
}

export interface VscodeDiagnostic {
  range: { start: { line: number, character: number }, end: { line: number, character: number } };
  severity: DiagnosticSeverity;
  source: string;
  code: string;
  message: string;
}

export class PolicyDiagnosticsAdapter {
  public static translateFindings(
    findings: { ruleId: string; file: string; line: number; message: string }[],
    effectivePolicy: SecurityPolicy
  ): VscodeDiagnostic[] {
    const diagnostics: VscodeDiagnostic[] = [];

    for (const finding of findings) {
      const policySeverity = effectivePolicy.enforcedRules[finding.ruleId] || 'warning';

      if (policySeverity === 'off') {
        continue;
      }

      const hasException = effectivePolicy.exceptions.some(
        ex => ex.targetRuleId === finding.ruleId && ex.scopePath === finding.file
      );

      if (hasException) {
        continue;
      }

      const vsCodeSeverity = 
        policySeverity === 'error' ? DiagnosticSeverity.Error : DiagnosticSeverity.Warning;

      diagnostics.push({
        range: {
          start: { line: Math.max(0, finding.line - 1), character: 0 },
          end: { line: Math.max(0, finding.line - 1), character: 250 }
        },
        severity: vsCodeSeverity,
        source: 'ChainProof Policy',
        code: finding.ruleId,
        message: `[${finding.ruleId}] ${finding.message}`
      });
    }

    return diagnostics;
  }
}
