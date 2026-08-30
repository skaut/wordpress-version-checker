# AGENTS.md

This file provides guidance to conding agents when working with code in this repository.

## What this is

A GitHub Action (`skaut/wordpress-version-checker`) that reads a WordPress plugin's readme "Tested up to:" line, compares it against the latest WordPress version from `api.wordpress.org`, and opens/updates/closes a `wpvc`-labelled issue in the repository accordingly. The action manifest is `action.yml`, which runs the bundled `dist/index.js` on `node20`.

## Commands

```bash
npm run build          # vite build -> dist/index.js (prebuild cleans dist/)
npm run lint           # eslint + tsc --noEmit in parallel
npm run lint:eslint    # eslint only
npm run lint:typecheck # tsc --noEmit only
npm test               # vitest (watch mode)
npm run test-coverage  # vitest run --coverage (what CI runs)

npx vitest run tests/run.test.ts          # single test file
npx vitest run -t "some test name"        # single test by name
```

## `dist/` is committed

`dist/index.js` is checked in because GitHub Actions runs it directly. Any change to `src/` requires `npm run build` and committing the resulting `dist/`. Both the `simple-git-hooks` pre-commit hook (`scripts/pre-commit.js`) and the CI "Check for clean repo" step fail if `dist/` is out of sync.

## Architecture

`src/index.ts` → `src/run.ts` is the whole control flow:

1. `wpvc-config.ts` fetches `.wordpress-version-checker.json` from the repo via the GitHub API and normalizes it into a fully-defaulted `Config` (`readme` candidate paths, `channel` defaulting to `"rc"`, `assignees`). A missing file (404) is not an error; anything malformed throws `ConfigError`.
2. `tested-version.ts` fetches the readme candidate paths in parallel, takes the first that resolves, and greps the `Tested up to:` line.
3. `wordpress-versions.ts` calls `api.wordpress.org/core/version-check/1.7/?channel=beta` over raw `node:https` and derives `{ stable, rc, beta }`.
4. `run.ts` compares with `compare-versions` and dispatches to exactly one of `outdated-stable.ts`, `outdated-rc.ts`, `outdated-beta.ts`, or `up-to-date.ts` — gated so that `rc`/`beta` versions are only considered when the configured channel opts in.
5. Each of those calls into `issue-management.ts` (`getIssue`/`createIssue`/`updateIssue`/`commentOnIssue`/`closeIssue`). Issues are identified by the `wpvc` label plus creator `github-actions[bot]`; `updateIssue` no-ops when title and body already match.

Cross-cutting pieces:

- `octokit.ts` and `repo.ts` are lazily-memoized singletons — never construct an Octokit client or read `github.context` directly, always call `octokit()` / `repo()`. This indirection is what makes tests mockable.
- All errors are `WPVCError` subclasses in `src/exceptions/`, each formatting its own user-facing message in its constructor. `run.ts` is the single catch site and reports via `core.setFailed`. New failure modes get a new exception class rather than an inline message.

## Testing conventions

`tests/setup.ts` (a vitest `setupFile`) calls `nock.disableNetConnect()` and globally mocks `src/octokit` to return an Octokit backed by `node-fetch` so `nock` can intercept it. Tests therefore stub GitHub HTTP calls with `nock`, and mock sibling modules with `vi.mock`. `mockReset: true` is set in `vite.config.ts`. Canned `api.wordpress.org` payloads live in `tests/version-check-responses/`.

## Lint notes

ESLint is strict (typescript-eslint strict + stylistic, perfectionist natural sorting, prettier, plus JSON/Markdown/package.json plugins). `eslint-comments/require-description` and `no-unused-disable` are errors, so every `eslint-disable` needs a `-- reason` comment and must actually suppress something. GitHub API snake_case fields need a `// eslint-disable-next-line camelcase -- API name` line.
