import { z } from 'zod';

export const PolicyScopeSchema = z.enum([
  'organization', 'repository', 'branch', 'path', 'contract', 'environment'
]);
export type PolicyScope = z.infer<typeof PolicyScopeSchema>;

export const RuleSeveritySchema = z.enum(['error', 'warning', 'off']);
export type RuleSeverity = z.infer<typeof RuleSeveritySchema>;

export const PolicyGatesSchema = z.object({
  maxFindings: z.number().int().nonnegative().optional(),
  preventNewRegressions: z.boolean().default(true),
  allowedCompilerVersions: z.array(z.string()).optional(),
  maxSuppressedAgeDays: z.number().int().positive().optional(),
  requiredAnalysisModes: z.array(z.string()).optional(),
}).strict();
export type PolicyGates = z.infer<typeof PolicyGatesSchema>;

export const ExceptionPayloadSchema = z.object({
  owner: z.string().min(3),
  justification: z.string().min(10),
  expiryTimestamp: z.number().int().positive(),
  targetRuleId: z.string(),
  scopePath: z.string(),
}).strict();

export const SignedExceptionSchema = ExceptionPayloadSchema.extend({
  signatureHash: z.string().length(64),
});
export type SignedException = z.infer<typeof SignedExceptionSchema>;
export type ExceptionPayload = z.infer<typeof ExceptionPayloadSchema>;

export const SecurityPolicySchema = z.object({
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  scope: PolicyScopeSchema,
  inheritsFrom: z.array(z.string()).optional(),
  enforcedRules: z.record(z.string(), RuleSeveritySchema),
  gates: PolicyGatesSchema,
  exceptions: z.array(SignedExceptionSchema).default([]),
}).strict();
export type SecurityPolicy = z.infer<typeof SecurityPolicySchema>;
