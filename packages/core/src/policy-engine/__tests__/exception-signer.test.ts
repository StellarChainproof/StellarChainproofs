import { generateDeterministicHash, validateExceptionIntegrity, TamperEvidentError } from '../crypto/exception-signer';
import { ExceptionPayload, SignedException } from '../schemas/policy.schema';

describe('Exception Signer (Crypto Integrity)', () => {
  const currentTimestamp = Math.floor(Date.now() / 1000);
  
  const validPayload: ExceptionPayload = {
    owner: 'security-team',
    justification: 'False positive in legacy math library',
    expiryTimestamp: currentTimestamp + 86400, // +1 day
    targetRuleId: 'reentrancy',
    scopePath: 'contracts/Legacy.sol'
  };

  it('should generate a deterministic hash regardless of key order', () => {
    const hash1 = generateDeterministicHash(validPayload);
    
    // Scrambled order object
    const scrambledPayload: ExceptionPayload = {
      scopePath: validPayload.scopePath,
      owner: validPayload.owner,
      targetRuleId: validPayload.targetRuleId,
      expiryTimestamp: validPayload.expiryTimestamp,
      justification: validPayload.justification
    };
    
    const hash2 = generateDeterministicHash(scrambledPayload);
    expect(hash1).toBe(hash2);
  });

  it('should throw TamperEvidentError on expired exceptions', () => {
    const expiredPayload: SignedException = { 
      ...validPayload, 
      expiryTimestamp: currentTimestamp - 3600, // -1 hour
      signatureHash: 'dummy-hash' 
    };
    expect(() => validateExceptionIntegrity(expiredPayload, currentTimestamp)).toThrow(TamperEvidentError);
  });

  it('should throw TamperEvidentError on tampered data', () => {
    const validHash = generateDeterministicHash(validPayload);
    const tamperedPayload: SignedException = { 
      ...validPayload, 
      signatureHash: validHash,
      justification: 'Hacked justification to bypass rules' // Altered payload
    };
    expect(() => validateExceptionIntegrity(tamperedPayload, currentTimestamp)).toThrow(TamperEvidentError);
  });
});
