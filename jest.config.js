/** @type {import('jest').Config} */
export default {
  collectCoverage: true,
  collectCoverageFrom: ["src/**/*", "!src/index.ts"],
  coverageDirectory: "coverage",
  coverageProvider: "babel",
  setupFiles: ["<rootDir>/__tests__/setup.ts"],
  transform: {
    // eslint-disable-next-line @typescript-eslint/naming-convention -- The key is a glob.
    "^.+\\.[jt]s$": [
      "ts-jest",
      {
        tsconfig: "<rootDir>/test.tsconfig.json",
      },
    ],
  },
  transformIgnorePatterns: ["node_modules/(?!node-fetch)/"],
  resetMocks: true,
  testMatch: ["<rootDir>/__tests__/**/*.test.ts"],
};
