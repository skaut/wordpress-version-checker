import type { Config } from "./interfaces/Config";
import { createIssue, getIssue, updateIssue } from "./issue-management";

function issueBody(testedVersion: string, latestVersion: string): string {
  return `There is a new WordPress version that the plugin hasn't been tested with. Please test it and then change the "Tested up to" field in the plugin readme.

**Tested up to:** ${testedVersion}
**Latest version:** ${latestVersion}

This issue will be closed automatically when the versions match.`;
}

export async function outdatedStable(
  config: Config,
  testedVersion: string,
  stableVersion: string,
): Promise<void> {
  const existingIssue = await getIssue();
  const title =
    "The plugin hasn't been tested with the latest version of WordPress";
  const body = issueBody(testedVersion, stableVersion);
  if (existingIssue !== null) {
    await updateIssue(existingIssue, title, body);
  } else {
    await createIssue(title, body, config.assignees);
  }
}
