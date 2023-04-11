import * as core from "@actions/core";
import { compare } from "compare-versions";

import type { WPVCError } from "./exceptions/WPVCError";
import { outdatedBeta } from "./outdated-beta";
import { outdatedRC } from "./outdated-rc";
import { outdatedStable } from "./outdated-stable";
import { testedVersion } from "./tested-version";
import { upToDate } from "./up-to-date";
import { wordpressVersions } from "./wordpress-versions";
import { WPVCConfig } from "./wpvc-config";

export async function run(): Promise<void> {
  try {
    const config = await WPVCConfig();
    const readmeVersion = await testedVersion(config);
    const availableVersions = await wordpressVersions();
    const betaVersion =
      config.channel === "beta" ? availableVersions.beta : null;
    const rcVersion = ["beta", "rc"].includes(config.channel)
      ? availableVersions.rc
      : null;
    if (compare(readmeVersion, availableVersions.stable, "<")) {
      await outdatedStable(config, readmeVersion, availableVersions.stable);
    } else if (rcVersion !== null && compare(readmeVersion, rcVersion, "<")) {
      await outdatedRC(config, readmeVersion, rcVersion);
    } else if (
      betaVersion !== null &&
      compare(readmeVersion, betaVersion, "<")
    ) {
      outdatedBeta();
    } else {
      await upToDate();
    }
  } catch (e) {
    core.setFailed((e as WPVCError).message);
  }
}
