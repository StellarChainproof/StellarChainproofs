import type {
  BenchmarkReport,
  GateConfig,
  GateEvaluationResult,
  GateCheckResult,
  ThresholdExceptionsFile,
  RuleThresholdException,
} from "./types";

/**
 * Evaluates a candidate benchmark report against a baseline report using regression thresholds.
 */
export function evaluateRegressionGate(
  candidate: BenchmarkReport,
  baseline?: BenchmarkReport,
  config: GateConfig = {},
  exceptionsFile?: ThresholdExceptionsFile,
): GateEvaluationResult {
  const checks: GateCheckResult[] = [];
  const exceptionsApplied: RuleThresholdException[] = [];

  const cMet = candidate.metrics;
  const bMet = baseline?.metrics;

  const minPrecision = config.minPrecision ?? 0.8;
  const minRecall = config.minRecall ?? 0.8;
  const minF1 = config.minF1 ?? 0.8;

  // Check 1: Minimum Precision threshold
  const precPassed = cMet.precision >= minPrecision;
  checks.push({
    name: "Minimum Precision",
    passed: precPassed,
    actual: Number(cMet.precision.toFixed(4)),
    threshold: minPrecision,
    message: precPassed
      ? `Precision ${cMet.precision.toFixed(4)} meets minimum threshold ${minPrecision}`
      : `Precision ${cMet.precision.toFixed(4)} is below minimum threshold ${minPrecision}`,
  });

  // Check 2: Minimum Recall threshold
  const recPassed = cMet.recall >= minRecall;
  checks.push({
    name: "Minimum Recall",
    passed: recPassed,
    actual: Number(cMet.recall.toFixed(4)),
    threshold: minRecall,
    message: recPassed
      ? `Recall ${cMet.recall.toFixed(4)} meets minimum threshold ${minRecall}`
      : `Recall ${cMet.recall.toFixed(4)} is below minimum threshold ${minRecall}`,
  });

  // Check 3: Minimum F1 Score threshold
  const f1Passed = cMet.f1Score >= minF1;
  checks.push({
    name: "Minimum F1 Score",
    passed: f1Passed,
    actual: Number(cMet.f1Score.toFixed(4)),
    threshold: minF1,
    message: f1Passed
      ? `F1 score ${cMet.f1Score.toFixed(4)} meets minimum threshold ${minF1}`
      : `F1 score ${cMet.f1Score.toFixed(4)} is below minimum threshold ${minF1}`,
  });

  // Baseline Comparison Checks (if baseline is available)
  if (bMet) {
    // Check 4: Precision Regression
    const maxPrecDrop = config.maxPrecisionDrop ?? 0.05;
    const precDelta = bMet.precision - cMet.precision;
    const precDropPassed = precDelta <= maxPrecDrop;
    checks.push({
      name: "Precision Drop vs Baseline",
      passed: precDropPassed,
      actual: Number(cMet.precision.toFixed(4)),
      threshold: Number((bMet.precision - maxPrecDrop).toFixed(4)),
      delta: Number((-precDelta).toFixed(4)),
      message: precDropPassed
        ? `Precision drop ${precDelta.toFixed(4)} is within allowed limit ${maxPrecDrop}`
        : `Precision dropped by ${precDelta.toFixed(4)} from baseline (${bMet.precision.toFixed(4)} -> ${cMet.precision.toFixed(4)})`,
    });

    // Check 5: Recall Regression
    const maxRecDrop = config.maxRecallDrop ?? 0.05;
    const recDelta = bMet.recall - cMet.recall;
    const recDropPassed = recDelta <= maxRecDrop;
    checks.push({
      name: "Recall Drop vs Baseline",
      passed: recDropPassed,
      actual: Number(cMet.recall.toFixed(4)),
      threshold: Number((bMet.recall - maxRecDrop).toFixed(4)),
      delta: Number((-recDelta).toFixed(4)),
      message: recDropPassed
        ? `Recall drop ${recDelta.toFixed(4)} is within allowed limit ${maxRecDrop}`
        : `Recall dropped by ${recDelta.toFixed(4)} from baseline (${bMet.recall.toFixed(4)} -> ${cMet.recall.toFixed(4)})`,
    });

    // Check 6: Runtime Regression
    if (config.maxRuntimeRegressionPct !== undefined) {
      const allowedPct = config.maxRuntimeRegressionPct;
      const pctIncrease = bMet.runtimeMs > 0 ? ((cMet.runtimeMs - bMet.runtimeMs) / bMet.runtimeMs) * 100 : 0;
      const runtimePassed = pctIncrease <= allowedPct;
      checks.push({
        name: "Runtime Regression vs Baseline",
        passed: runtimePassed,
        actual: `${cMet.runtimeMs}ms (${pctIncrease.toFixed(1)}%)`,
        threshold: `${(bMet.runtimeMs * (1 + allowedPct / 100)).toFixed(0)}ms (+${allowedPct}%)`,
        delta: Number(pctIncrease.toFixed(1)),
        message: runtimePassed
          ? `Runtime increase ${pctIncrease.toFixed(1)}% is within allowed ${allowedPct}%`
          : `Runtime increased by ${pctIncrease.toFixed(1)}% over baseline (${bMet.runtimeMs}ms -> ${cMet.runtimeMs}ms)`,
      });
    }

    // Check 7: New False Positives
    if (config.allowNewFalsePositives === false) {
      const newFpPassed = cMet.falsePositives <= bMet.falsePositives;
      checks.push({
        name: "No New False Positives",
        passed: newFpPassed,
        actual: cMet.falsePositives,
        threshold: bMet.falsePositives,
        delta: cMet.falsePositives - bMet.falsePositives,
        message: newFpPassed
          ? `False positives count (${cMet.falsePositives}) did not increase from baseline (${bMet.falsePositives})`
          : `False positives increased by ${cMet.falsePositives - bMet.falsePositives} from baseline`,
      });
    }
  }

  // Apply Exceptions File overrides if provided
  if (exceptionsFile && exceptionsFile.exceptions.length > 0) {
    const now = new Date();
    for (const exc of exceptionsFile.exceptions) {
      if (exc.expiresAt && new Date(exc.expiresAt) < now) {
        continue;
      }

      // If exception covers specific rule or general threshold
      for (const check of checks) {
        if (!check.passed) {
          if (exc.ruleId) {
            const ruleMetrics = cMet.perRule[exc.ruleId];
            if (ruleMetrics) {
              if (
                (exc.minPrecision !== undefined && ruleMetrics.precision >= exc.minPrecision) ||
                (exc.minRecall !== undefined && ruleMetrics.recall >= exc.minRecall)
              ) {
                check.passed = true;
                check.waivedByException = true;
                check.message += ` [Waived by rule exception: ${exc.reason}]`;
                exceptionsApplied.push(exc);
              }
            }
          } else {
            check.passed = true;
            check.waivedByException = true;
            check.message += ` [Waived by general exception: ${exc.reason}]`;
            exceptionsApplied.push(exc);
          }
        }
      }
    }
  }

  const overallPassed = checks.every((c) => c.passed);
  const summary = overallPassed
    ? `Benchmark comparison gate PASSED (${checks.length} checks satisfied)`
    : `Benchmark comparison gate FAILED (${checks.filter((c) => !c.passed).length} of ${checks.length} checks failed)`;

  return {
    passed: overallPassed,
    checks,
    summary,
    exceptionsApplied,
  };
}
