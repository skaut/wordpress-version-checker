import { octokit } from "./octokit";
import { repo } from "./repo";

import type { Config } from "./interfaces/Config"; // eslint-disable-line @typescript-eslint/no-unused-vars
import { hasStatus } from "./has-status";

import { ConfigError } from "./exceptions/ConfigError";

function isConfig(
  config: Record<string, unknown>
): config is Config & Record<string, unknown> {
  if ("readme" in config) {
    return true;
  }
  return false;
}

export async function WPVCConfig(): Promise<Config | null> {
  const file = await octokit()
    .rest.repos.getContent({ ...repo, path: ".wordpress-version-checker.json" })
    .catch(function (e: unknown): never | null {
      if (hasStatus(e) && e.status === 404) {
        return null;
      } else {
        throw new ConfigError(String(e));
      }
    });
  if (file === null) {
    return null;
  }
  const encodedContent = (file.data as { content?: string }).content;
  if (encodedContent === undefined) {
    throw new ConfigError("Failed to decode the file.");
  }
  let config: Record<string, unknown> = {};
  try {
    config = JSON.parse(
      Buffer.from(encodedContent, "base64").toString()
    ) as Record<string, unknown>;
  } catch (e) {
    throw new ConfigError((e as SyntaxError).message);
  }
  if (!isConfig(config)) {
    throw new ConfigError("Invalid config file.");
  }
  return config;
}
