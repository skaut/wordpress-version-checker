import * as core from "@actions/core";
import { compare } from "compare-versions";

import type { WPVCError } from "./exceptions/WPVCError"; // eslint-disable-line @typescript-eslint/no-unused-vars
import type { Config } from "./interfaces/Config"; // eslint-disable-line @typescript-eslint/no-unused-vars
import {
  closeIssue,
  createIssue,
  getIssue,
  updateIssue,
} from "./issue-management";
import { testedVersion } from "./tested-version";
import { wordpressVersions } from "./wordpress-versions";
import { WPVCConfig } from "./wpvc-config";

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
    await closeIssue(existingIssue);
  }
}

export async function run(): Promise<void> {
  try {
    const config = await WPVCConfig();
    const readmeVersion = await testedVersion(config);
    const availableVersions = await wordpressVersions();
    if (compare(readmeVersion, availableVersions.stable, "<")) {
      await outdated(config, readmeVersion, availableVersions.stable);
    } else {
      await upToDate();
    }
  } catch (e) {
    core.setFailed((e as WPVCError).message);
  }
}
