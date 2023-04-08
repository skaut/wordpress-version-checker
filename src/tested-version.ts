import { InvalidReadmeError } from "./exceptions/InvalidReadmeError";
import { hasStatus } from "./has-status";
import type { Config } from "./interfaces/Config"; // eslint-disable-line @typescript-eslint/no-unused-vars
import { octokit } from "./octokit";
import { repo } from "./repo";

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
    const matches = [...line.matchAll(/^[\s]*Tested up to: ?([.\d]+)$/g)];
    if (matches.length !== 1) {
      continue;
    }
    return matches[0][1];
  }
  throw new InvalidReadmeError('No "Tested up to:" line found');
}
