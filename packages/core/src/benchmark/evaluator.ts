import type { Finding, Severity } from "../types";
import type {
  ExpectedFinding,
  CorpusTestCase,
  TestCaseBenchmarkResult,
  MatchedFindingPair,
  BenchmarkMetrics,
  RuleBenchmarkMetrics,
  MetricSummary,
  CorpusCaseCategory,
} from "./types";

/**
 * Normalizes file paths for matching across platforms.
 */
function normalizePath(p: string): string {
  return p.replace(/\\/g, "/").toLowerCase();
}

/**
 * Matches an actual finding against an expected finding assertion.
 */
export function matchFindingAssertion(
  expected: ExpectedFinding,
  actual: Finding,
): { matches: boolean; matchedByAlternative: boolean; lineDelta: number } {
  // Check primary expectation match
  const primaryMatch = isFindingMatchingSpec(
    expected.ruleId,
    expected.severity,
    expected.file,
    expected.line,
    expected.lineTolerance ?? 2,
    expected.snippet,
    expected.callPath,
    expected.evidence,
    expected.confidence,
    actual,
  );

  if (primaryMatch.matches) {
    return {
      matches: true,
      matchedByAlternative: false,
      lineDelta: primaryMatch.lineDelta,
    };
  }

  // Check allowed alternatives if specified
  if (expected.allowedAlternatives && expected.allowedAlternatives.length > 0) {
    for (const alt of expected.allowedAlternatives) {
      const altRuleId = alt.ruleId || expected.ruleId;
      const altSeverity = alt.severity || expected.severity;
      const altLine = alt.line !== undefined ? alt.line : expected.line;
      const altTolerance = alt.lineTolerance !== undefined ? alt.lineTolerance : (expected.lineTolerance ?? 2);

      const altMatch = isFindingMatchingSpec(
        altRuleId,
        altSeverity,
        expected.file,
        altLine,
        altTolerance,
        expected.snippet,
        expected.callPath,
        expected.evidence,
        expected.confidence,
        actual,
      );

      if (altMatch.matches) {
        return {
          matches: true,
          matchedByAlternative: true,
          lineDelta: altMatch.lineDelta,
        };
      }
    }
  }

  return { matches: false, matchedByAlternative: false, lineDelta: Infinity };
}

function isFindingMatchingSpec(
  ruleId: string,
  severitySpec: Severity | Severity[] | undefined,
  fileSpec: string | undefined,
  lineSpec: number | undefined,
  lineTolerance: number,
  snippetSpec: string | undefined,
  callPathSpec: string[] | undefined,
  evidenceSpec: string[] | undefined,
  confidenceSpec: "high" | "medium" | "low" | undefined,
  actual: Finding,
): { matches: boolean; lineDelta: number } {
  // Rule ID match
  if (actual.id !== ruleId && actual.swcId !== ruleId) {
    return { matches: false, lineDelta: Infinity };
  }

  // Severity match
  if (severitySpec) {
    if (Array.isArray(severitySpec)) {
      if (!severitySpec.includes(actual.severity)) {
        return { matches: false, lineDelta: Infinity };
      }
    } else if (actual.severity !== severitySpec) {
      return { matches: false, lineDelta: Infinity };
    }
  }

  // Confidence match
  if (confidenceSpec && actual.confidence && actual.confidence !== confidenceSpec) {
    return { matches: false, lineDelta: Infinity };
  }

  // File match
  if (fileSpec && actual.file) {
    const normSpec = normalizePath(fileSpec);
    const normActual = normalizePath(actual.file);
    if (!normActual.endsWith(normSpec) && !normSpec.endsWith(normActual)) {
      return { matches: false, lineDelta: Infinity };
    }
  }

  // Line number match with line tolerance
  let lineDelta = 0;
  if (lineSpec !== undefined && actual.line !== undefined) {
    lineDelta = Math.abs(actual.line - lineSpec);
    if (lineDelta > lineTolerance) {
      return { matches: false, lineDelta };
    }
  }

  // Snippet match
  if (snippetSpec && actual.snippet) {
    if (!actual.snippet.toLowerCase().includes(snippetSpec.toLowerCase())) {
      return { matches: false, lineDelta };
    }
  }

  // Call path trace match
  if (callPathSpec && callPathSpec.length > 0) {
    if (!actual.callPath || actual.callPath.length === 0) {
      return { matches: false, lineDelta };
    }
    const actualJoined = actual.callPath.join("->").toLowerCase();
    const expectedJoined = callPathSpec.join("->").toLowerCase();
    if (!actualJoined.includes(expectedJoined)) {
      return { matches: false, lineDelta };
    }
  }

  // Evidence trace match
  if (evidenceSpec && evidenceSpec.length > 0) {
    if (!actual.evidence || actual.evidence.length === 0) {
      return { matches: false, lineDelta };
    }
    const actualEvText = actual.evidence.map((e) => e.description).join(" ").toLowerCase();
    for (const ev of evidenceSpec) {
      if (!actualEvText.includes(ev.toLowerCase())) {
        return { matches: false, lineDelta };
      }
    }
  }

  return { matches: true, lineDelta };
}

/**
 * Evaluates a single corpus test case against actual findings emitted by scanner.
 */
export function evaluateTestCase(
  testCase: CorpusTestCase,
  actualFindings: Finding[],
  runtimeMs: number,
  error?: string,
  mutatedVariant?: string,
): TestCaseBenchmarkResult {
  if (error) {
    return {
      caseId: testCase.id,
      caseName: testCase.name,
      category: testCase.category,
      passed: false,
      expectedCount: testCase.expectedFindings.length,
      actualCount: 0,
      truePositives: 0,
      falsePositives: 0,
      falseNegatives: testCase.expectedFindings.length,
      trueNegatives: 0,
      matchedFindings: [],
      unmatchedActual: [],
      unmatchedExpected: testCase.expectedFindings,
      runtimeMs,
      error,
      mutatedVariant,
    };
  }

  const remainingActual = [...actualFindings];
  const matchedFindings: MatchedFindingPair[] = [];
  const unmatchedExpected: ExpectedFinding[] = [];

  for (const expected of testCase.expectedFindings) {
    let bestMatchIndex = -1;
    let bestMatchDelta = Infinity;
    let bestMatchByAlt = false;

    for (let i = 0; i < remainingActual.length; i++) {
      const actual = remainingActual[i];
      const matchResult = matchFindingAssertion(expected, actual);
      if (matchResult.matches && matchResult.lineDelta < bestMatchDelta) {
        bestMatchIndex = i;
        bestMatchDelta = matchResult.lineDelta;
        bestMatchByAlt = matchResult.matchedByAlternative;
      }
    }

    if (bestMatchIndex !== -1) {
      const actualMatched = remainingActual.splice(bestMatchIndex, 1)[0];
      matchedFindings.push({
        expected,
        actual: actualMatched,
        matchedByAlternative: bestMatchByAlt,
        lineDelta: bestMatchDelta,
      });
    } else {
      unmatchedExpected.push(expected);
    }
  }

  const unmatchedActual = remainingActual;
  const truePositives = matchedFindings.length;
  const falseNegatives = unmatchedExpected.length;
  const falsePositives = unmatchedActual.length;

  // True Negative calculation: if case expected 0 findings and 0 actual findings were produced
  let trueNegatives = 0;
  if (testCase.expectedFindings.length === 0 && actualFindings.length === 0) {
    trueNegatives = 1;
  }

  // Passed condition: TP matches expected count and FP == 0 (or all FP are allowed false positives)
  const fpAreAllowed = unmatchedActual.every(() =>
    testCase.expectedFindings.some((ef) => ef.allowedFalsePositive),
  );

  let expectedCountSatisfied = true;
  if (testCase.expectedFindingCount !== undefined) {
    expectedCountSatisfied = actualFindings.length === testCase.expectedFindingCount;
  }

  const passed =
    falseNegatives === 0 &&
    (falsePositives === 0 || fpAreAllowed) &&
    expectedCountSatisfied;

  return {
    caseId: testCase.id,
    caseName: testCase.name,
    category: testCase.category,
    passed,
    expectedCount: testCase.expectedFindings.length,
    actualCount: actualFindings.length,
    truePositives,
    falsePositives,
    falseNegatives,
    trueNegatives,
    matchedFindings,
    unmatchedActual,
    unmatchedExpected,
    runtimeMs,
    mutatedVariant,
  };
}

export function computePrecision(tp: number, fp: number): number {
  if (tp + fp === 0) return 1.0;
  return tp / (tp + fp);
}

export function computeRecall(tp: number, fn: number): number {
  if (tp + fn === 0) return 1.0;
  return tp / (tp + fn);
}

export function computeFScore(precision: number, recall: number, beta: number = 1.0): number {
  if (precision + recall === 0) return 0;
  const betaSq = beta * beta;
  return ((1 + betaSq) * (precision * recall)) / (betaSq * precision + recall);
}

/**
 * Calculates aggregate benchmark metrics across all evaluated test case results.
 */
export function calculateBenchmarkMetrics(
  results: TestCaseBenchmarkResult[],
  totalRuntimeMs: number,
  peakMemoryBytes: number,
): BenchmarkMetrics {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;

  const perRuleMap: Record<
    string,
    { tp: number; fp: number; fn: number; expected: number; matched: number }
  > = {};

  const categories: CorpusCaseCategory[] = [
    "vulnerable",
    "fixed",
    "ambiguous",
    "multi-file",
    "generated",
    "real-world",
  ];

  const perCategoryMap: Record<
    CorpusCaseCategory,
    { cases: number; tp: number; fp: number; fn: number; tn: number }
  > = {
    vulnerable: { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 },
    fixed: { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 },
    ambiguous: { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 },
    "multi-file": { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 },
    generated: { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 },
    "real-world": { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 },
  };

  const falsePositiveCategories: Record<string, number> = {};

  for (const res of results) {
    tp += res.truePositives;
    fp += res.falsePositives;
    fn += res.falseNegatives;
    tn += res.trueNegatives;

    // Per category breakdown
    const cat = perCategoryMap[res.category] || { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 };
    cat.cases += 1;
    cat.tp += res.truePositives;
    cat.fp += res.falsePositives;
    cat.fn += res.falseNegatives;
    cat.tn += res.trueNegatives;
    perCategoryMap[res.category] = cat;

    // Per rule breakdown - Matched TP
    for (const match of res.matchedFindings) {
      const ruleId = match.actual.id || match.actual.swcId || match.expected.ruleId;
      if (!perRuleMap[ruleId]) {
        perRuleMap[ruleId] = { tp: 0, fp: 0, fn: 0, expected: 0, matched: 0 };
      }
      perRuleMap[ruleId].tp += 1;
      perRuleMap[ruleId].matched += 1;
      perRuleMap[ruleId].expected += 1;
    }

    // Per rule breakdown - Unmatched Expected (FN)
    for (const unexp of res.unmatchedExpected) {
      const ruleId = unexp.ruleId;
      if (!perRuleMap[ruleId]) {
        perRuleMap[ruleId] = { tp: 0, fp: 0, fn: 0, expected: 0, matched: 0 };
      }
      perRuleMap[ruleId].fn += 1;
      perRuleMap[ruleId].expected += 1;
    }

    // Per rule breakdown - Unmatched Actual (FP)
    for (const unact of res.unmatchedActual) {
      const ruleId = unact.id || unact.swcId || "unknown";
      if (!perRuleMap[ruleId]) {
        perRuleMap[ruleId] = { tp: 0, fp: 0, fn: 0, expected: 0, matched: 0 };
      }
      perRuleMap[ruleId].fp += 1;

      // Classify FP
      const matchingExpectedSpec = res.unmatchedExpected.find((e) => e.ruleId === ruleId);
      const fpCat = matchingExpectedSpec?.fpCategory || "other";
      falsePositiveCategories[fpCat] = (falsePositiveCategories[fpCat] || 0) + 1;
    }
  }

  const precision = computePrecision(tp, fp);
  const recall = computeRecall(tp, fn);
  const f1Score = computeFScore(precision, recall, 1.0);
  const f2Score = computeFScore(precision, recall, 2.0);
  const f05Score = computeFScore(precision, recall, 0.5);

  const perRule: Record<string, RuleBenchmarkMetrics> = {};
  for (const [ruleId, stats] of Object.entries(perRuleMap)) {
    const rPrec = computePrecision(stats.tp, stats.fp);
    const rRec = computeRecall(stats.tp, stats.fn);
    const rF1 = computeFScore(rPrec, rRec, 1.0);
    const coverageRatio = stats.expected > 0 ? stats.matched / stats.expected : 1.0;

    perRule[ruleId] = {
      ruleId,
      truePositives: stats.tp,
      falsePositives: stats.fp,
      falseNegatives: stats.fn,
      precision: rPrec,
      recall: rRec,
      f1Score: rF1,
      coverage: {
        totalExpected: stats.expected,
        matched: stats.matched,
        coverageRatio,
      },
    };
  }

  const perCategory: Record<CorpusCaseCategory, MetricSummary> = {} as Record<
    CorpusCaseCategory,
    MetricSummary
  >;

  for (const cat of categories) {
    const stats = perCategoryMap[cat];
    const cPrec = computePrecision(stats.tp, stats.fp);
    const cRec = computeRecall(stats.tp, stats.fn);
    const cF1 = computeFScore(cPrec, cRec, 1.0);
    perCategory[cat] = {
      cases: stats.cases,
      truePositives: stats.tp,
      falsePositives: stats.fp,
      falseNegatives: stats.fn,
      trueNegatives: stats.tn,
      precision: cPrec,
      recall: cRec,
      f1Score: cF1,
    };
  }

  return {
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    trueNegatives: tn,
    precision,
    recall,
    f1Score,
    f2Score,
    f05Score,
    perRule,
    perCategory,
    falsePositiveCategories,
    runtimeMs: totalRuntimeMs,
    peakMemoryBytes,
  };
}
