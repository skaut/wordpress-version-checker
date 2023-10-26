import * as https from "https";

import { LatestVersionError } from "./exceptions/LatestVersionError";
import type { VersionCheckResponse } from "./interfaces/VersionCheckResponse";
import type { WordpressVersions } from "./interfaces/WordpressVersions";

async function httpsRequest(options: https.RequestOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    https
      .get(options, (response) => {
        let data = "";
        response.setEncoding("utf8");
        response.on("data", (chunk): void => {
          data += chunk;
        });
        response.on("end", (): void => {
          if (response.statusCode === 200) {
            resolve(data);
          } else {
            reject();
          }
        });
      })
      .on("error", (e) => {
        reject(e);
      });
  });
}

function isBetaVersion(version: string): boolean {
  const splitVersion = version.split("-");
  return splitVersion.length >= 2 && splitVersion[1].startsWith("beta");
}

function isRCVersion(version: string): boolean {
  const splitVersion = version.split("-");
  return splitVersion.length >= 2 && splitVersion[1].startsWith("RC");
}

function normalizeVersion(version: string): string {
  return version.split("-")[0].split(".").slice(0, 2).join("."); // Discard patch version and RC designations
}

export async function wordpressVersions(): Promise<WordpressVersions> {
  const rawData = await httpsRequest({
    host: "api.wordpress.org",
    path: "/core/version-check/1.7/?channel=beta",
  }).catch((e: string): never => {
    throw new LatestVersionError(e);
  });
  let response: VersionCheckResponse = {};
  try {
    response = JSON.parse(rawData) as VersionCheckResponse;
  } catch (e) {
    throw new LatestVersionError((e as SyntaxError).message);
  }
  if (response.offers === undefined) {
    throw new LatestVersionError("Couldn't find the latest version");
  }
  const latest = response.offers.find(
    (record): boolean => record.response === "upgrade",
  );
  if (latest?.current === undefined) {
    throw new LatestVersionError("Couldn't find the latest version");
  }
  const development = response.offers.find(
    (record): boolean => record.response === "development",
  );
  return {
    beta:
      development?.current !== undefined &&
      (isBetaVersion(development.current) || isRCVersion(development.current))
        ? normalizeVersion(development.current)
        : null,
    rc:
      development?.current !== undefined && isRCVersion(development.current)
        ? normalizeVersion(development.current)
        : null,
    stable: normalizeVersion(latest.current),
  };
}
