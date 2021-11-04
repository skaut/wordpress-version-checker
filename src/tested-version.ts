import { octokit } from "./octokit";
import { repo } from "./repo";

import { hasStatus } from "./has-status";
import type { Config } from "./interfaces/Config"; // eslint-disable-line @typescript-eslint/no-unused-vars

import { InvalidReadmeError } from "./exceptions/InvalidReadmeError";

async function readme(config: Config | null): Promise<string> {
  let readmeLocations = ["readme.txt", "plugin/readme.txt"];
  if (config !== null) {
    readmeLocations = [config.readme];
  }
  for (const readmeLocation of readmeLocations) {
    const result = await octokit()
      .rest.repos.getContent({ ...repo(), path: readmeLocation })
      .catch(function (e: unknown): never | null {
        if (hasStatus(e) && e.status === 404) {
          return null;
        } else {
          throw new InvalidReadmeError(
            "No readme file was found in repo and all usual locations were exhausted. Error message: " +
              String(e)
          );
        }
      });
    if (result === null) {
      continue;
    }
    const encodedContent = (result.data as { content?: string }).content;
    if (encodedContent === undefined) {
      throw new InvalidReadmeError(
        "No readme file was found in repo and all usual locations were exhausted."
      );
    }
    return Buffer.from(encodedContent, "base64").toString();
  }
  throw new InvalidReadmeError(
    "No readme file was found in repo and all usual locations were exhausted."
  );
}

export async function testedVersion(config: Config | null): Promise<string> {
  const readmeContents = await readme(config);
  for (const line of readmeContents.split("\n")) {
    if (!line.startsWith("Tested up to:")) {
      continue;
    }
    const matches = line.match(/[^:\s]+/g);
    if (!matches) {
      throw new InvalidReadmeError('No "Tested up to:" line found');
    }
    const version = matches.pop();
    if (version === undefined) {
      throw new InvalidReadmeError('No "Tested up to:" line found');
    }
    return version;
  }
  throw new InvalidReadmeError('No "Tested up to:" line found');
}
