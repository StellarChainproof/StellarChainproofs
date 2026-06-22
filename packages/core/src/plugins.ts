import * as fs from "fs";
import * as path from "path";
import type { ChainProofPlugin, PluginRule } from "./types";

/**
 * Load a plugin from a package name or file path.
 * Supports:
 * - npm packages: "@myteam/chainproof-rules"
 * - relative paths: "./local-rules/my-plugin.js"
 * - absolute paths: "/full/path/to/plugin.js"
 *
 * Returns null if plugin fails to load (non-fatal).
 */
export function loadPlugin(
  specifier: string,
  cwd: string = process.cwd(),
): ChainProofPlugin | null {
  try {
    let modulePath: string;

    // Determine if this is a file path or npm package
    if (specifier.startsWith(".") || specifier.startsWith("/")) {
      // File path
      modulePath = path.isAbsolute(specifier)
        ? specifier
        : path.resolve(cwd, specifier);

      if (!fs.existsSync(modulePath)) {
        console.warn(`[ChainProof] Plugin not found: ${modulePath}`);
        return null;
      }
    } else {
      // Try npm package first, then fallback to relative path
      try {
        modulePath = require.resolve(specifier, {
          paths: [cwd, process.cwd()],
        });
      } catch (e) {
        // Try as a relative file path
        const asFile = path.resolve(cwd, specifier);
        if (fs.existsSync(asFile)) {
          modulePath = asFile;
        } else {
          console.warn(`[ChainProof] Could not resolve plugin: ${specifier}`);
          return null;
        }
      }
    }

    // Load and validate the plugin
    const plugin = require(modulePath);
    const loaded = plugin.default || plugin;

    if (!isValidPlugin(loaded)) {
      console.warn(
        `[ChainProof] Plugin at ${specifier} does not export a valid ChainProofPlugin. ` +
          `Expected { name, version, rules }. Got: ${JSON.stringify(Object.keys(loaded))}`,
      );
      return null;
    }

    return loaded;
  } catch (error) {
    console.warn(
      `[ChainProof] Failed to load plugin "${specifier}": ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return null;
  }
}

/**
 * Load multiple plugins, returning only the ones that loaded successfully.
 */
export function loadPlugins(
  specifiers: string[],
  cwd?: string,
): ChainProofPlugin[] {
  return specifiers
    .map((spec) => loadPlugin(spec, cwd))
    .filter((plugin): plugin is ChainProofPlugin => plugin !== null);
}

/**
 * Validate that an object is a valid ChainProofPlugin.
 */
function isValidPlugin(obj: unknown): obj is ChainProofPlugin {
  if (typeof obj !== "object" || obj === null) return false;

  const p = obj as Record<string, unknown>;
  return (
    typeof p.name === "string" &&
    typeof p.version === "string" &&
    Array.isArray(p.rules) &&
    p.rules.every(isValidRule)
  );
}

/**
 * Validate that an object is a valid PluginRule.
 */
function isValidRule(obj: unknown): obj is PluginRule {
  if (typeof obj !== "object" || obj === null) return false;

  const r = obj as Record<string, unknown>;
  return (
    typeof r.id === "string" &&
    typeof r.title === "string" &&
    typeof r.severity === "string" &&
    typeof r.description === "string" &&
    typeof r.detect === "function"
  );
}
