import { SecurityPolicy, RuleSeverity, PolicyGates, SignedException } from '../schemas/policy.schema';
import { validateExceptionIntegrity } from '../crypto/exception-signer';

export class PolicyConflictError extends Error {
  constructor(message: string) {
    super(`[PolicyConflictError]: ${message}`);
    this.name = 'PolicyConflictError';
  }
}

export class PolicyResolver {
  /**
   * Evaluates and merges an array of security policies.
   * Enforces strict severity inheritance to prevent child scopes from downgrading rules.
   */
  public static resolve(policies: SecurityPolicy[]): SecurityPolicy {
    if (!policies || policies.length === 0) {
      throw new Error('No policies provided for resolution.');
    }
    return policies.reduce((base, override) => this.merge(base, override));
  }

  private static merge(base: SecurityPolicy, child: SecurityPolicy): SecurityPolicy {
    return {
      version: base.version, 
      scope: child.scope, 
      inheritsFrom: [...(base.inheritsFrom || []), ...(child.inheritsFrom || [])],
      enforcedRules: this.mergeRules(base.enforcedRules, child.enforcedRules),
      gates: this.mergeGates(base.gates, child.gates),
      exceptions: this.mergeExceptions(base.exceptions, child.exceptions),
    };
  }

  private static mergeRules(
    baseRules: Record<string, RuleSeverity>,
    childRules: Record<string, RuleSeverity>
  ): Record<string, RuleSeverity> {
    const resolved = { ...baseRules };

    for (const [ruleId, childSeverity] of Object.entries(childRules)) {
      const baseSeverity = baseRules[ruleId];

      if (baseSeverity === 'error' && (childSeverity === 'warning' || childSeverity === 'off')) {
        throw new PolicyConflictError(
          `Rule '${ruleId}' severity cannot be downgraded from 'error' to '${childSeverity}'.`
        );
      }
      resolved[ruleId] = childSeverity;
    }
    return resolved;
  }

  private static mergeGates(baseGates: PolicyGates, childGates: PolicyGates): PolicyGates {
    const resolvedMaxFindings = 
      baseGates.maxFindings !== undefined && childGates.maxFindings !== undefined
        ? Math.min(baseGates.maxFindings, childGates.maxFindings)
        : (childGates.maxFindings ?? baseGates.maxFindings);

    return {
      maxFindings: resolvedMaxFindings,
      preventNewRegressions: baseGates.preventNewRegressions || childGates.preventNewRegressions,
      allowedCompilerVersions: childGates.allowedCompilerVersions ?? baseGates.allowedCompilerVersions,
      maxSuppressedAgeDays: childGates.maxSuppressedAgeDays ?? baseGates.maxSuppressedAgeDays,
      requiredAnalysisModes: [
        ...new Set([...(baseGates.requiredAnalysisModes || []), ...(childGates.requiredAnalysisModes || [])])
      ],
    };
  }

  private static mergeExceptions(
    baseExceptions: SignedException[],
    childExceptions: SignedException[]
  ): SignedException[] {
    const validExceptions: SignedException[] = [];

    for (const ex of [...baseExceptions, ...childExceptions]) {
      try {
        validateExceptionIntegrity(ex);
        validExceptions.push(ex);
      } catch (e) {
        console.warn(`Dropped invalid exception for rule ${ex.targetRuleId}`);
      }
    }
    return validExceptions;
  }
}
