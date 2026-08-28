import * as fs from "fs";
import * as path from "path";
import {
  BENCHMARK_CORPUS_SCHEMA_VERSION,
  BENCHMARK_EXCEPTIONS_SCHEMA_VERSION,
  CorpusManifest,
  CorpusTestCase,
  ThresholdExceptionsFile,
  BenchmarkDiagnostic,
} from "./types";

export class CorpusSchemaError extends Error {
  constructor(
    message: string,
    public readonly diagnostics: BenchmarkDiagnostic[],
  ) {
    super(message);
    this.name = "CorpusSchemaError";
  }
}

/**
 * Validates and parses a raw JSON object or file path as a CorpusManifest.
 */
export function parseCorpusManifest(
  input: string | Record<string, unknown>,
  baseDir?: string,
): { manifest: CorpusManifest; diagnostics: BenchmarkDiagnostic[] } {
  const diagnostics: BenchmarkDiagnostic[] = [];
  let raw: Record<string, unknown>;
  let manifestPath: string | undefined;

  if (typeof input === "string") {
    manifestPath = path.resolve(input);
    if (!fs.existsSync(manifestPath)) {
      diagnostics.push({
        code: "FILE_NOT_FOUND",
        severity: "error",
        message: `Corpus manifest file not found: ${manifestPath}`,
        target: manifestPath,
      });
      throw new CorpusSchemaError(`Corpus manifest file not found: ${manifestPath}`, diagnostics);
    }
    try {
      const content = fs.readFileSync(manifestPath, "utf-8");
      raw = JSON.parse(content) as Record<string, unknown>;
    } catch (err) {
      diagnostics.push({
        code: "CORRUPT_MANIFEST",
        severity: "error",
        message: `Failed to parse JSON in manifest ${manifestPath}: ${err instanceof Error ? err.message : String(err)}`,
        target: manifestPath,
      });
      throw new CorpusSchemaError(`Corrupt manifest JSON: ${manifestPath}`, diagnostics);
    }
  } else {
    raw = input;
  }

  if (typeof raw !== "object" || raw === null) {
    diagnostics.push({
      code: "INVALID_SCHEMA",
      severity: "error",
      message: "Manifest content must be a JSON object",
    });
    throw new CorpusSchemaError("Manifest content must be a JSON object", diagnostics);
  }

  // Schema version check & migration if needed
  if (!raw.schemaVersion) {
    diagnostics.push({
      code: "INVALID_SCHEMA",
      severity: "warning",
      message: `Missing schemaVersion in manifest, assuming ${BENCHMARK_CORPUS_SCHEMA_VERSION}`,
    });
    raw.schemaVersion = BENCHMARK_CORPUS_SCHEMA_VERSION;
  } else if (raw.schemaVersion !== BENCHMARK_CORPUS_SCHEMA_VERSION) {
    diagnostics.push({
      code: "INVALID_SCHEMA",
      severity: "error",
      message: `Unsupported schemaVersion '${raw.schemaVersion}'. Expected '${BENCHMARK_CORPUS_SCHEMA_VERSION}'`,
    });
    throw new CorpusSchemaError(`Unsupported schemaVersion '${raw.schemaVersion}'`, diagnostics);
  }

  if (typeof raw.corpusName !== "string" || raw.corpusName.trim() === "") {
    diagnostics.push({
      code: "INVALID_SCHEMA",
      severity: "error",
      message: "Manifest 'corpusName' must be a non-empty string",
    });
  }

  if (!Array.isArray(raw.cases)) {
    diagnostics.push({
      code: "INVALID_SCHEMA",
      severity: "error",
      message: "Manifest 'cases' must be an array",
    });
    throw new CorpusSchemaError("Manifest 'cases' must be an array", diagnostics);
  }

  const caseIds = new Set<string>();
  const validatedCases: CorpusTestCase[] = [];
  const rootDir = baseDir || (manifestPath ? path.dirname(manifestPath) : process.cwd());

  for (let i = 0; i < raw.cases.length; i++) {
    const c = raw.cases[i] as Record<string, unknown>;
    if (typeof c !== "object" || c === null) {
      diagnostics.push({
        code: "INVALID_SCHEMA",
        severity: "error",
        message: `Case at index ${i} is not a valid object`,
      });
      continue;
    }

    if (typeof c.id !== "string" || !c.id) {
      diagnostics.push({
        code: "INVALID_SCHEMA",
        severity: "error",
        message: `Case at index ${i} missing required string 'id'`,
      });
      continue;
    }

    if (caseIds.has(c.id)) {
      diagnostics.push({
        code: "DUPLICATE_CASE",
        severity: "error",
        message: `Duplicate case id '${c.id}' found in manifest`,
        target: c.id,
      });
    } else {
      caseIds.add(c.id);
    }

    const category = c.category as string;
    const validCategories = ["vulnerable", "fixed", "ambiguous", "multi-file", "generated", "real-world"];
    if (!validCategories.includes(category)) {
      diagnostics.push({
        code: "INVALID_SCHEMA",
        severity: "error",
        message: `Case '${c.id}' has invalid category '${category}'. Valid categories: ${validCategories.join(", ")}`,
        target: c.id,
      });
    }

    if (!Array.isArray(c.targets) || c.targets.length === 0) {
      diagnostics.push({
        code: "INVALID_SCHEMA",
        severity: "error",
        message: `Case '${c.id}' must specify at least one target path in 'targets'`,
        target: c.id,
      });
    } else {
      for (const targetPath of c.targets) {
        if (typeof targetPath !== "string") {
          diagnostics.push({
            code: "INVALID_SCHEMA",
            severity: "error",
            message: `Case '${c.id}' contains non-string target path`,
            target: c.id,
          });
          continue;
        }
        const resolvedTarget = path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
        if (!fs.existsSync(resolvedTarget)) {
          diagnostics.push({
            code: "FILE_NOT_FOUND",
            severity: "warning",
            message: `Case '${c.id}' target file does not exist: ${resolvedTarget}`,
            target: resolvedTarget,
          });
        }
      }
    }

    if (!Array.isArray(c.expectedFindings)) {
      diagnostics.push({
        code: "INVALID_SCHEMA",
        severity: "error",
        message: `Case '${c.id}' expectedFindings must be an array`,
        target: c.id,
      });
    }

    validatedCases.push(c as unknown as CorpusTestCase);
  }

  const errors = diagnostics.filter((d) => d.severity === "error");
  if (errors.length > 0) {
    throw new CorpusSchemaError(`Manifest validation failed with ${errors.length} error(s)`, diagnostics);
  }

  const manifest: CorpusManifest = {
    schemaVersion: BENCHMARK_CORPUS_SCHEMA_VERSION,
    corpusName: raw.corpusName as string,
    description: raw.description as string | undefined,
    cases: validatedCases,
    metadata: raw.metadata as Record<string, unknown> | undefined,
  };

  return { manifest, diagnostics };
}

/**
 * Validates and parses a ThresholdExceptionsFile JSON.
 */
export function parseThresholdExceptions(
  filePath: string,
): ThresholdExceptionsFile {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Threshold exceptions file not found: ${resolved}`);
  }
  const content = fs.readFileSync(resolved, "utf-8");
  const raw = JSON.parse(content) as Record<string, unknown>;

  if (raw.schemaVersion !== BENCHMARK_EXCEPTIONS_SCHEMA_VERSION) {
    throw new Error(`Invalid threshold exceptions schema version. Expected ${BENCHMARK_EXCEPTIONS_SCHEMA_VERSION}`);
  }
  if (!Array.isArray(raw.exceptions)) {
    throw new Error("Threshold exceptions 'exceptions' must be an array");
  }

  return raw as unknown as ThresholdExceptionsFile;
}
