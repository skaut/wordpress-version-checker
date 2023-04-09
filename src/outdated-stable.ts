import type { Config } from "./interfaces/Config";
import { createIssue, updateIssue } from "./issue-management";

export async function outdatedStable(
  config: Config | null,
  testedVersion: string,
  latestVersion: string,
  existingIssue: number | null
): Promise<void> {
  if (existingIssue !== null) {
    await updateIssue(existingIssue, testedVersion, latestVersion);
  } else {
    await createIssue(config, testedVersion, latestVersion);
  }
}
