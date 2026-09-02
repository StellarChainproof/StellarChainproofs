import { createHash } from 'crypto';
import { ExceptionPayload, SignedException } from '../schemas/policy.schema';

export class TamperEvidentError extends Error {
  constructor(message: string) {
    super(`[TamperEvidentError]: ${message}`);
    this.name = 'TamperEvidentError';
  }
}

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }

  if (typeof value === 'object') {
    const ordered = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${ordered
      .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`)
      .join(',')}}`;
  }

  return JSON.stringify(value);
}

export function generateDeterministicHash(payload: ExceptionPayload): string {
  return createHash('sha256').update(stableStringify(payload)).digest('hex');
}

export function validateExceptionIntegrity(
  exception: SignedException,
  currentTimestamp = Math.floor(Date.now() / 1000)
): void {
  if (!exception) {
    throw new TamperEvidentError('Exception payload is required.');
  }

  if (exception.expiryTimestamp <= currentTimestamp) {
    throw new TamperEvidentError(
      `Exception for rule '${exception.targetRuleId}' is expired or invalid.`
    );
  }

  const expectedHash = generateDeterministicHash({
    owner: exception.owner,
    justification: exception.justification,
    expiryTimestamp: exception.expiryTimestamp,
    targetRuleId: exception.targetRuleId,
    scopePath: exception.scopePath,
  });

  if (exception.signatureHash !== expectedHash) {
    throw new TamperEvidentError(
      `Exception signature mismatch for rule '${exception.targetRuleId}'.`
    );
  }
}
