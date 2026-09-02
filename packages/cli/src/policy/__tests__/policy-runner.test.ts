import { PolicyRunner, ScanFinding } from '../policy-runner';
import { MarkdownReporter } from '../markdown-reporter';
import { SecurityPolicy } from '@chainproof/core';

jest.mock('fs');

describe('PolicyRunner & Reporter Integration', () => {
  const mockPolicy: SecurityPolicy = {
    version: '1.0.0',
    scope: 'organization',
    enforcedRules: { 'reentrancy': 'error', 'gas-limit': 'off' },
    gates: { maxFindings: 1, preventNewRegressions: true },
    exceptions: []
  };

  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('should correctly filter findings based on policy and evaluate gates', () => {
    const rawFindings: ScanFinding[] = [
      { id: '1', ruleId: 'reentrancy', file: 'contracts/Vault.sol', line: 10 },
      { id: '2', ruleId: 'gas-limit', file: 'contracts/Vault.sol', line: 15 },
      { id: '3', ruleId: 'reentrancy', file: 'contracts/Token.sol', line: 42 }
    ];

    const result = PolicyRunner.enforce(mockPolicy, rawFindings, 0);

    expect(result.enforcedFindings.length).toBe(2);
    expect(result.enforcedFindings[0].ruleId).toBe('reentrancy');
    expect(result.passed).toBe(false);
    expect(result.rejections.length).toBe(2);
  });

  it('MarkdownReporter should sanitize absolute paths and not leak system info', () => {
    const dirtyFindings: ScanFinding[] = [
      { id: '1', ruleId: 'unsafe-call', file: '/home/runner/work/StellarChainproofs/packages/core/src/index.ts', line: 5 }
    ];

    const result = PolicyRunner.enforce(mockPolicy, dirtyFindings, 0);
    const markdown = MarkdownReporter.generateCiReport(result);

    expect(markdown).not.toContain('/home/runner/work/');
    expect(markdown).toContain('packages/core/src/index.ts');
  });
});
