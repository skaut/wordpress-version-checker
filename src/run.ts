import compareVersions from "compare-versions";

import { octokit } from "./octokit";
import { repo } from "./repo";
import { createIssue, updateIssue } from "./issue-management";
import { latestWordPressVersion } from "./latest-version";
import { testedVersion } from "./tested-version";
import { WPVCConfig } from "./wpvc-config";

import type { Config } from "./interfaces/Config"; // eslint-disable-line @typescript-eslint/no-unused-vars

import { IssueListError } from "./exceptions/IssueListError";
import type { WPVCError } from "./exceptions/WPVCError"; // eslint-disable-line @typescript-eslint/no-unused-vars

async function outdated(
  config: Config | null,
  testedVersion: string,
  latestVersion: string
): Promise<void> {
  const issues = await octokit()
    .rest.issues.listForRepo({
      ...repo(),
      creator: "github-actions[bot]",
      labels: "wpvc",
    })
    .catch(function (e): never {
      throw new IssueListError(String(e));
    });
  if (issues.data.length === 0) {
    await createIssue(config, testedVersion, latestVersion);
  } else {
    await updateIssue(issues.data[0].number, testedVersion, latestVersion);
  }
}

async function upToDate(): Promise<void> {
  const issues = await octokit()
    .rest.issues.listForRepo({
      ...repo(),
      creator: "github-actions[bot]",
      labels: "wpvc",
    })
    .catch(function (e): never {
      throw new IssueListError(String(e));
    });
  for (const issue of issues.data) {
    void octokit().rest.issues.update({
      ...repo(),
      issue_number: issue.number,
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
