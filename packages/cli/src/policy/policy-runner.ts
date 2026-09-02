import { readFileSync } from 'fs';
import { resolve } from 'path';
import { SecurityPolicy, SecurityPolicySchema } from '@chainproof/core/src/policy-engine/schemas/policy.schema';
import { PolicyResolver } from '@chainproof/core/src/policy-engine/resolver/policy-resolver';

export interface ScanFinding {
  id: string;
  ruleId: string;
  file: string;
  line: number;
}

export interface EnforcementResult {
  passed: boolean;
  effectivePolicy: SecurityPolicy;
  enforcedFindings: ScanFinding[];
  rejections: string[];
}

export class PolicyRunner {
  public static loadAndResolvePolicies(filePaths: string[]): SecurityPolicy {
    const policies: SecurityPolicy[] = filePaths.map(filePath => {
      try {
        const absolutePath = resolve(process.cwd(), filePath);
        const rawContent = readFileSync(absolutePath, 'utf-8');
        return SecurityPolicySchema.parse(JSON.parse(rawContent));
      } catch (error) {
        throw new Error(`Policy load failed at ${filePath}: ${error instanceof Error ? error.message : 'Unknown'}`);
      }
    });

    return PolicyResolver.resolve(policies);
  }

  public static enforce(
    effectivePolicy: SecurityPolicy,
    rawFindings: ScanFinding[],
    baselineFindingsCount: number = 0
  ): EnforcementResult {
    const rejections: string[] = [];
    const enforcedFindings: ScanFinding[] = [];

    for (const finding of rawFindings) {
      const severity = effectivePolicy.enforcedRules[finding.ruleId] || 'warning';
      
      if (severity === 'off') {
        continue;
      }

      const hasException = effectivePolicy.exceptions.some(
        ex => ex.targetRuleId === finding.ruleId && ex.scopePath === finding.file
      );

      if (hasException) {
        continue;
      }

      enforcedFindings.push(finding);
    }

    let passed = true;

    if (
      effectivePolicy.gates.maxFindings !== undefined && 
      enforcedFindings.length > effectivePolicy.gates.maxFindings
    ) {
      passed = false;
      rejections.push(`Threshold exceeded: ${enforcedFindings.length} findings (max: ${effectivePolicy.gates.maxFindings}).`);
    }

    if (
      effectivePolicy.gates.preventNewRegressions && 
      enforcedFindings.length > baselineFindingsCount
    ) {
      passed = false;
      rejections.push(`Regression detected: ${enforcedFindings.length} findings (baseline: ${baselineFindingsCount}).`);
    }

    return { passed, effectivePolicy, enforcedFindings, rejections };
  }
}
