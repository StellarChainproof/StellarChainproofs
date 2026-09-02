import { PolicyResolver, PolicyConflictError } from '../resolver/policy-resolver';
import { SecurityPolicy } from '../schemas/policy.schema';

describe('PolicyResolver', () => {
  const orgPolicy: SecurityPolicy = {
    version: '1.0.0',
    scope: 'organization',
    enforcedRules: { 'reentrancy': 'error', 'tx-origin': 'warning' },
    gates: { maxFindings: 10, preventNewRegressions: true },
    exceptions: []
  };

  it('merges policies and enforces strictest thresholds', () => {
    const repoPolicy: SecurityPolicy = {
      version: '1.0.0',
      scope: 'repository',
      enforcedRules: { 'tx-origin': 'error', 'floating-pragma': 'warning' },
      gates: { maxFindings: 5, preventNewRegressions: true },
      exceptions: []
    };
    
    const resolved = PolicyResolver.resolve([orgPolicy, repoPolicy]);
    
    expect(resolved.enforcedRules['reentrancy']).toBe('error');
    expect(resolved.enforcedRules['tx-origin']).toBe('error');
    expect(resolved.enforcedRules['floating-pragma']).toBe('warning');
    expect(resolved.gates.maxFindings).toBe(5);
  });

  it('rejects severity downgrades from child policies', () => {
    const invalidOverridePolicy: SecurityPolicy = {
      version: '1.0.0',
      scope: 'repository',
      enforcedRules: { 'reentrancy': 'off' }, 
      gates: { preventNewRegressions: true },
      exceptions: []
    };
    
    expect(() => PolicyResolver.resolve([orgPolicy, invalidOverridePolicy])).toThrow(PolicyConflictError);
  });
});
