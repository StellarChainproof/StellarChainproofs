import { TenantPolicy } from "./types";
import { ScanConfig } from "../types";

export class TenantPolicyEnforcer {
  private policy: TenantPolicy;

  constructor(policy?: Partial<TenantPolicy>) {
    this.policy = {
      tenantId: policy?.tenantId ?? "default",
      allowLLM: policy?.allowLLM ?? false,
      allowSlither: policy?.allowSlither ?? true,
      maxFilesPerScan: policy?.maxFilesPerScan ?? 100,
      maxFileSize: policy?.maxFileSize ?? 10 * 1024 * 1024,
      ...policy,
    };
  }

  public enforceScanConfig(config: ScanConfig): ScanConfig {
    const enforced = { ...config };

    if (!this.policy.allowLLM && enforced.useLLM) {
      console.warn(
        `[TenantPolicyEnforcer] LLM transmission denied by tenant policy for tenant '${this.policy.tenantId}'. Disabling LLM.`
      );
      enforced.useLLM = false;
      enforced.apiKey = undefined;
    }

    if (!this.policy.allowSlither && enforced.useSlither) {
      enforced.useSlither = false;
    }

    return enforced;
  }

  public getPolicy(): TenantPolicy {
    return { ...this.policy };
  }
}
