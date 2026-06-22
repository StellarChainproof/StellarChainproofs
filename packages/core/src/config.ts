import * as fs from "fs";
import * as path from "path";
import { loadPlugins } from "./plugins";
import type { ScanConfig, ChainProofPlugin } from "./types";

export interface ChainProofConfig {
  plugins?: string[];
  [key: string]: unknown;
}

/**
 * Load .chainproofrc.json from the given directory or a parent directory.
 * Returns the loaded config or null if not found.
 */
export function loadConfigFile(
  startDir: string = process.cwd(),
): ChainProofConfig | null {
  let dir = path.resolve(startDir);

  // Search up to 5 levels up the directory tree
  for (let i = 0; i < 5; i++) {
    const configPath = path.join(dir, ".chainproofrc.json");

    if (fs.existsSync(configPath)) {
      try {
        const content = fs.readFileSync(configPath, "utf-8");
        return JSON.parse(content);
      } catch (error) {
        console.warn(`[ChainProof] Failed to parse ${configPath}: ${error}`);
        return null;
      }
    }

    const parent = path.dirname(dir);
    if (parent === dir) break; // reached root
    dir = parent;
  }

  return null;
}

/**
 * Merge plugins from config file into ScanConfig.
 * Command-line plugins (passed in config) take precedence over config-file plugins.
 */
export function mergePluginsFromConfig(
  config: ScanConfig,
  configFile?: ChainProofConfig | null,
): ScanConfig {
  if (!configFile?.plugins || config.plugins) {
    // config.plugins already set or no file plugins
    return config;
  }

  const filePlugins = loadPlugins(configFile.plugins);
  return {
    ...config,
    plugins: filePlugins,
  };
}
