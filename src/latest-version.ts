import * as https from "https";

import { LatestVersionError } from "./exceptions/LatestVersionError";

async function httpsRequest(options: https.RequestOptions): Promise<string> {
  return new Promise(function (resolve, reject) {
    https.get(options, function (response) {
      let data = "";
      response.setEncoding("utf8");
      response.on("data", (chunk): void => {
        data += chunk;
      });
      response.on("error", (e): void => reject(e));
      response.on("end", function (): void {
        if (response.statusCode === 200) {
          resolve(data);
        } else {
          reject();
        }
      });
    });
  });
}

export async function latestWordPressVersion(): Promise<string> {
  const rawData = await httpsRequest({
    host: "api.wordpress.org",
    path: "/core/stable-check/1.0/",
  }).catch(function (e: string): never {
    throw new LatestVersionError(e);
  });
  let list: Record<string, unknown> = {};
  try {
    list = JSON.parse(rawData) as Record<string, unknown>;
  } catch (e) {
    throw new LatestVersionError((e as SyntaxError).message);
  }
  const latest = Object.keys(list).find(
    (key): boolean => list[key] === "latest"
  );
  if (!latest) {
    throw new LatestVersionError("Couldn't find the latest version");
  }
  return latest.split(".").slice(0, 2).join("."); // Discard patch version
}
