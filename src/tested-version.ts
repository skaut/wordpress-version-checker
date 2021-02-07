import { octokit } from "./octokit";
import { repo } from "./repo";

import { WPVCConfig } from "./wpvc-config";
import { hasStatus } from "./has-status";

import { ConfigError } from "./exceptions/ConfigError";
import { InvalidReadmeError } from "./exceptions/InvalidReadmeError";

async function readme(): Promise<string> {
  let readmeLocations = ["readme.txt", "plugin/readme.txt"];
  const config = await WPVCConfig();
  if (config !== null) {
    readmeLocations = [config.readme];
  }
  for (const readmeLocation of readmeLocations) {
    const result = await octokit.repos
      .getContent({ ...repo, path: readmeLocation })
      .catch(function (e): null | never {
        if (hasStatus(e) && e.status === 404) {
          return null;
        } else {
          throw new ConfigError(
            "No config file was found in repo and all usual locations were exhausted. Error message: " +
              String(e)
          );
        }
      });
    if (result === null) {
      continue;
    }
    const encodedContent = (result.data as { content?: string }).content;
    if (!encodedContent) {
      throw new ConfigError(
        "No config file was found in repo and all usual locations were exhausted."
      );
    }
    return Buffer.from(encodedContent, "base64").toString();
  }
  throw new ConfigError(
    "No config file was found in repo and all usual locations were exhausted."
  );
}

export async function testedVersion(): Promise<string> {
  const readmeContents = await readme();
  for (const line of readmeContents.split("\n")) {
    if (!line.startsWith("Tested up to:")) {
      continue;
    }
    const matches = line.match(/[^:\s]+/g);
    if (!matches) {
      throw new InvalidReadmeError();
    }
    const version = matches.pop();
    if (!version) {
      throw new InvalidReadmeError();
    }
    return version;
  }
  throw new InvalidReadmeError();
}
