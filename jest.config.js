/** @type {import('jest').Config} */
export default {
  collectCoverage: true,
  collectCoverageFrom: ["src/**/*", "!src/index.ts"],
  coverageDirectory: "coverage",
  coverageProvider: "babel",
  resetMocks: true,
  setupFiles: ["<rootDir>/__tests__/setup.ts"],
  testMatch: ["<rootDir>/__tests__/**/*.test.ts"],
  transform: {
    "^.+\\.[jt]s$": [
      "ts-jest",
      {
        tsconfig: "<rootDir>/test.tsconfig.json",
      },
    ],
  },
  transformIgnorePatterns: ["node_modules/(?!node-fetch)/"],
};
