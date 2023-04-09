import * as https from "https";

import { LatestVersionError } from "./exceptions/LatestVersionError";
import type { VersionCheckResponse } from "./interfaces/VersionCheckResponse";
import type { VersionOffers } from "./interfaces/VersionOffers";

async function httpsRequest(options: https.RequestOptions): Promise<string> {
  return new Promise(function (resolve, reject) {
    https
      .get(options, function (response) {
        let data = "";
        response.setEncoding("utf8");
        response.on("data", (chunk): void => {
          data += chunk;
        });
        response.on("end", function (): void {
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

export async function wordpressVersions(): Promise<VersionOffers> {
  const rawData = await httpsRequest({
    host: "api.wordpress.org",
    path: "/core/version-check/1.7/?channel=beta",
  }).catch(function (e: string): never {
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
    (record): boolean => record["response"] === "latest"
  );
  if (latest?.current === undefined) {
    throw new LatestVersionError("Couldn't find the latest version");
  }
  return {
    beta: null,
    rc: null,
    stable: latest.current.split(".").slice(0, 2).join("."), // Discard patch version
  };
}
