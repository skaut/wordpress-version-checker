import type { Config } from "./interfaces/Config";

import { createIssue, getIssue, updateIssue } from "./issue-management";

function issueBody(testedVersion: string, latestVersion: string): string {
  return `There is an upcoming WordPress version in the **release candidate** stage that the plugin hasn't been tested with. Please test it and then change the "Tested up to" field in the plugin readme.

**Tested up to:** ${testedVersion}
**Upcoming version:** ${latestVersion}

This issue will be closed automatically when the versions match.`;
}

export async function outdatedRC(
  config: Config,
  testedVersion: string,
  rcVersion: string,
): Promise<void> {
  const existingIssue = await getIssue();
  const title =
    "The plugin hasn't been tested with an upcoming version of WordPress";
  const body = issueBody(testedVersion, rcVersion);
  if (existingIssue !== null) {
    await updateIssue(existingIssue, title, body);
  } else {
    await createIssue(title, body, config.assignees);
  }
}
