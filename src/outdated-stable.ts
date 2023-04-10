import type { Config } from "./interfaces/Config";
import { createIssue, getIssue, updateIssue } from "./issue-management";

export async function outdatedStable(
  config: Config,
  testedVersion: string,
  latestVersion: string
): Promise<void> {
  const existingIssue = await getIssue();
  if (existingIssue !== null) {
    await updateIssue(existingIssue, testedVersion, latestVersion);
  } else {
    await createIssue(config, testedVersion, latestVersion);
  }
}
