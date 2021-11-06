import compareVersions from "compare-versions";

import { octokit } from "./octokit";
import { repo } from "./repo";
import { createIssue, getIssue, updateIssue } from "./issue-management";
import { latestWordPressVersion } from "./latest-version";
import { testedVersion } from "./tested-version";
import { WPVCConfig } from "./wpvc-config";

import type { Config } from "./interfaces/Config"; // eslint-disable-line @typescript-eslint/no-unused-vars

import type { WPVCError } from "./exceptions/WPVCError"; // eslint-disable-line @typescript-eslint/no-unused-vars

async function outdated(
  config: Config | null,
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

async function upToDate(): Promise<void> {
  const existingIssue = await getIssue();
  if (existingIssue !== null) {
    void octokit().rest.issues.update({
      ...repo(),
      issue_number: existingIssue,
      state: "closed",
    });
  }
}

export async function run(): Promise<void> {
  try {
    const config = await WPVCConfig();
    const readmeVersion = await testedVersion(config);
    const latestVersion = await latestWordPressVersion();
    if (compareVersions.compare(readmeVersion, latestVersion, "<")) {
      await outdated(config, readmeVersion, latestVersion);
    } else {
      await upToDate();
    }
  } catch (e) {
    console.log((e as WPVCError).message);
  }
}
