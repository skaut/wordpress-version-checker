/** @type {import('jest').Config} */
export default {
  collectCoverage: true,
  collectCoverageFrom: ["src/**/*", "!src/index.ts"],
  coverageDirectory: "coverage",
  coverageProvider: "babel",
  setupFiles: ["<rootDir>/__tests__/setup.ts"],
  preset: "ts-jest/presets/default",
  resetMocks: true,
  testMatch: ["<rootDir>/__tests__/**/*.test.ts"],
};
