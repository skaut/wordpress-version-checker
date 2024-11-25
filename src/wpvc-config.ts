import type { Config } from "./interfaces/Config";

import { ConfigError } from "./exceptions/ConfigError";
import { octokit } from "./octokit";
import { repo } from "./repo";

export async function getWPVCConfig(): Promise<Config> {
  const file = await octokit()
    .rest.repos.getContent({
      ...repo(),
      path: ".wordpress-version-checker.json",
    })
    .catch((e: unknown): never | null => {
      if (hasStatus(e) && e.status === 404) {
        return null;
      }
      throw new ConfigError(String(e));
    });
  if (file === null) {
    return normalizeConfig({});
  }
  const encodedContent = (file.data as { content?: string }).content;
  if (encodedContent === undefined) {
    throw new ConfigError("Failed to decode the file.");
  }
  let config: unknown = undefined;
  try {
    config = JSON.parse(Buffer.from(encodedContent, "base64").toString());
  } catch (e) {
    throw new ConfigError((e as SyntaxError).message);
  }
  return normalizeConfig(config);
}

function hasStatus(obj: unknown): obj is Record<"status", unknown> {
  return Object.prototype.hasOwnProperty.call(obj, "status");
}

function normalizeConfig(rawConfig: unknown): Config {
  if (typeof rawConfig !== "object" || rawConfig === null) {
    throw new ConfigError("Invalid config file.");
  }
  // Default values
  const config: Config = {
    assignees: [],
    channel: "rc",
    readme: [
      "readme.txt",
      "src/readme.txt",
      "plugin/readme.txt",
      "readme.md",
      "src/readme.md",
      "plugin/readme.md",
    ],
  };
  if ("readme" in rawConfig) {
    if (typeof rawConfig.readme === "string") {
      config.readme = [rawConfig.readme];
    } else if (
      Array.isArray(rawConfig.readme) &&
      rawConfig.readme.every((item) => typeof item === "string")
    ) {
      config.readme = rawConfig.readme;
    } else {
      throw new ConfigError(
        'Invalid config file, the "readme" field should be a string or an array of strings.',
      );
    }
  }
  if ("assignees" in rawConfig) {
    if (
      !Array.isArray(rawConfig.assignees) ||
      !rawConfig.assignees.every((item) => typeof item === "string")
    ) {
      throw new ConfigError(
        'Invalid config file, the "assignees" field should be an array of strings.',
      );
    }
    config.assignees = rawConfig.assignees;
  }
  if ("channel" in rawConfig) {
    if (
      typeof rawConfig.channel !== "string" ||
      !["beta", "rc", "stable"].includes(rawConfig.channel)
    ) {
      throw new ConfigError(
        'Invalid config file, the "channel" field should be one of "beta", "rc" or "stable".',
      );
    }
    config.channel = rawConfig.channel as "beta" | "rc" | "stable";
  }
  return config;
}
