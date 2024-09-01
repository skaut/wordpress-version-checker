import type { Config } from "./interfaces/Config";
import { createIssue, getIssue, updateIssue } from "./issue-management";

function issueBody(testedVersion: string, latestVersion: string): string {
  return `There is an upcoming WordPress version in the **beta** stage that the plugin hasn't been tested with.

**Tested up to:** ${testedVersion}
**Beta version:** ${latestVersion}

This issue will be closed automatically when the versions match.`;
}

export async function outdatedBeta(
  config: Config,
  testedVersion: string,
  betaVersion: string,
): Promise<void> {
  const existingIssue = await getIssue();
  const title =
    "The plugin hasn't been tested with a beta version of WordPress";
  const body = issueBody(testedVersion, betaVersion);
  if (existingIssue !== null) {
    await updateIssue(existingIssue, title, body);
  } else {
    await createIssue(title, body, config.assignees);
  }
}
