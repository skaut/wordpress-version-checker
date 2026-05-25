#!/usr/bin/env node
// Pre-commit hook: verifies that dist/ is in sync with the build.
// Mirrors the CI check: `npm run build && git diff --exit-code -- dist/`.

import { execSync } from "child_process";

function run(cmd, opts = {}) {
  return execSync(cmd, { encoding: "utf8", ...opts }).trim();
}

console.log("Pre-commit: building dist/ to verify it is up to date…");
execSync("npm run build", { stdio: "inherit" });

// Check whether the build produced any changes to dist/ (staged or unstaged).
const changedFiles = run("git diff --name-only -- dist/");

if (changedFiles !== "") {
  console.error(
    "\x1b[31mPre-commit check failed: dist/ is out of sync with the source.\x1b[0m",
  );
  process.exit(1);
}

console.log("Pre-commit: dist/ is up to date.");
process.exit(0);
