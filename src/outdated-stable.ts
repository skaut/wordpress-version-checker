import type { Config } from "./interfaces/Config";
import { createIssue, getIssue, updateIssue } from "./issue-management";

function issueBody(testedVersion: string, latestVersion: string): string {
  return (
    'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n' +
    "\n" +
    "**Tested up to:** " +
    testedVersion +
    "\n" +
    "**Latest version:** " +
    latestVersion +
    "\n" +
    "\n" +
    "This issue will be closed automatically when the versions match."
  );
}

export async function outdatedStable(
  config: Config,
  testedVersion: string,
  latestVersion: string
): Promise<void> {
  const existingIssue = await getIssue();
  if (existingIssue !== null) {
    await updateIssue(existingIssue, testedVersion, latestVersion);
  } else {
    await createIssue(
      "The plugin hasn't been tested with the latest version of WordPress",
      issueBody(testedVersion, latestVersion),
      config.assignees
    );
  }
}
