import * as core from "@actions/core";
import { compare } from "compare-versions";

import type { WPVCError } from "./exceptions/WPVCError";
import type { VersionOffers } from "./interfaces/VersionOffers";
import { getIssue } from "./issue-management";
import { outdatedBeta } from "./outdated-beta";
import { outdatedRC } from "./outdated-rc";
import { outdatedStable } from "./outdated-stable";
import { testedVersion } from "./tested-version";
import { upToDate } from "./up-to-date";
import { wordpressVersions } from "./wordpress-versions";
import { WPVCConfig } from "./wpvc-config";

function isUpToDate(
  channel: "beta" | "rc" | "stable",
  availableVersions: VersionOffers,
  readmeVersion: string
): boolean {
  const minVersion =
    (channel === "beta" ? availableVersions.beta : null) ??
    (["beta", "rc"].includes(channel) ? availableVersions.rc : null) ??
    availableVersions.stable;
  return compare(minVersion, readmeVersion, "<=");
}

export async function run(): Promise<void> {
  try {
    const config = await WPVCConfig();
    const readmeVersion = await testedVersion(config);
    const availableVersions = await wordpressVersions();
    const channel = config?.channel ?? "stable";
    if (isUpToDate(channel, availableVersions, readmeVersion)) {
      await upToDate();
      return;
    }
    const rcVersion = ["beta", "rc"].includes(channel)
      ? availableVersions.rc
      : null;
    const existingIssue = await getIssue();
    if (rcVersion !== null && compare(rcVersion, readmeVersion, "<=")) {
      outdatedBeta();
    } else if (compare(availableVersions.stable, readmeVersion, "<=")) {
      outdatedRC();
    } else {
      await outdatedStable(
        config,
        readmeVersion,
        availableVersions.stable,
        existingIssue
      );
    }
  } catch (e) {
    core.setFailed((e as WPVCError).message);
  }
}
