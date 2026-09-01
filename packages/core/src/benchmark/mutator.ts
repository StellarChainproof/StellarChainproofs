import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export type MutationType = "line-shift" | "comment-noise" | "format-churn";

export interface MutatedVariantResult {
  variantPath: string;
  mutationType: MutationType;
  cleanup: () => void;
}

/**
 * Creates mutated variant copies of target Solidity fixture files to test detector stability.
 */
export function createMutatedVariant(
  targetPath: string,
  mutationType: MutationType,
  seed: number = 42,
): MutatedVariantResult {
  const absolutePath = path.resolve(targetPath);
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Target file for mutation does not exist: ${absolutePath}`);
  }

  const originalContent = fs.readFileSync(absolutePath, "utf-8");
  const lines = originalContent.split("\n");

  let mutatedLines: string[];

  switch (mutationType) {
    case "line-shift":
      // Insert top-level comments to shift line numbers by fixed offset
      mutatedLines = [
        "// BENCHMARK MUTATION VARIANT: LINE SHIFT",
        "// Shifted line offset +3",
        "// Standard AST preservation check",
        "",
        ...lines,
      ];
      break;

    case "comment-noise":
      // Inject random inline/block comments into source lines
      mutatedLines = lines.map((line, idx) => {
        if (line.trim().startsWith("//") || line.trim().startsWith("/*") || line.trim() === "") {
          return line;
        }
        if (idx % 3 === 0) {
          return `${line} /* benchmark_noise_${seed}_${idx} */`;
        }
        return line;
      });
      break;

    case "format-churn":
      // Change indentation / trailing whitespace without altering tokens
      mutatedLines = lines.map((line) => {
        if (line.startsWith("    ")) {
          return "  " + line.trimStart();
        }
        return line + " ";
      });
      break;

    default:
      mutatedLines = lines;
  }

  const mutatedContent = mutatedLines.join("\n");
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "cp-mutant-"));
  const fileName = path.basename(absolutePath);
  const mutantPath = path.join(tempDir, fileName);

  fs.writeFileSync(mutantPath, mutatedContent, "utf-8");

  const cleanup = () => {
    try {
      if (fs.existsSync(mutantPath)) {
        fs.unlinkSync(mutantPath);
      }
      if (fs.existsSync(tempDir)) {
        fs.rmdirSync(tempDir);
      }
    } catch {
      // Best-effort cleanup
    }
  };

  return {
    variantPath: mutantPath,
    mutationType,
    cleanup,
  };
}
