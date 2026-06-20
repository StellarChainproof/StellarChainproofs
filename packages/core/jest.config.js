/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  rootDir: "src",
  testMatch: ["**/__tests__/**/*.test.ts"],
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        tsconfig: "<rootDir>/../tsconfig.json",
        // Skip type-checking during tests — mirrors the tsc build's skipLibCheck behaviour
        // for third-party types (@solidity-parser/parser uses internal-only ASTNode typings).
        isolatedModules: true,
      },
    ],
  },
  collectCoverageFrom: [
    "**/*.ts",
    "!**/__tests__/**",
    "!**/index.ts",
    "!**/llm/**",
    // slither.ts wraps an external binary — covered by integration; excluded from threshold
    "!**/ast/slither.ts",
  ],
  coverageThreshold: {
    global: {
      lines: 85,
    },
  },
};
