import type { Config } from "./interfaces/Config";

import { InvalidReadmeError } from "./exceptions/InvalidReadmeError";
import { octokit } from "./octokit";
import { repo } from "./repo";

async function readme(config: Config): Promise<string> {
  const readmePromises = config.readme.map(async (readmeLocation) =>
    octokit()
      .rest.repos.getContent({ ...repo(), path: readmeLocation })
      .then((result) => {
        const encodedContent = (result.data as { content?: string }).content;
        if (encodedContent === undefined) {
          throw new Error();
        }
        return Buffer.from(encodedContent, "base64").toString();
      }),
  );
  for (const promiseResult of await Promise.allSettled(readmePromises)) {
    if (promiseResult.status === "fulfilled") {
      return promiseResult.value;
    }
  }
  throw new InvalidReadmeError(
    "No readme file was found in repo and all usual locations were exhausted.",
  );
}

export async function testedVersion(config: Config): Promise<string> {
  const readmeContents = await readme(config);
  for (const line of readmeContents.split(/\r?\n/u)) {
    const matches = [
      ...line.matchAll(/^[\s]*Tested up to:[\s]*([.\d]+)[\s]*$/gu),
    ];
    if (matches.length !== 1) {
      continue;
    }
    return matches[0][1];
  }
  throw new InvalidReadmeError('No "Tested up to:" line found');
}
