import nock from "nock";
import { mocked } from "jest-mock";
import mockedEnv from "mocked-env";

import * as core from "@actions/core";

import { WPVCConfig } from "../src/wpvc-config";

import { ConfigError } from "../src/exceptions/ConfigError";

jest.mock("@actions/core");

describe("Mocked env variables", () => {
  let restore: () => void;

  beforeEach(() => {
    restore = mockedEnv({ GITHUB_REPOSITORY: "OWNER/REPO" });
    mocked(core).getInput.mockReturnValue("GH_TOKEN");
  });
  afterEach(() => {
    restore();
  });

  test("WPVCConfig works correctly", async () => {
    const config = {
      readme: "path/to/readme.txt",
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(WPVCConfig()).resolves.toStrictEqual(config);
  });

  test("WPVCConfig works correctly with assignees", async () => {
    const config = {
      readme: "path/to/readme.txt",
      assignees: ["PERSON1", "PERSON2"],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(WPVCConfig()).resolves.toStrictEqual(config);
  });

  test("WPVCConfig fails gracefully on connection issues", async () => {
    await expect(WPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("WPVCConfig returns null on no config", async () => {
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(404);

    await expect(WPVCConfig()).resolves.toStrictEqual(null);
  });

  test("WPVCConfig fails gracefully on invalid response", async () => {
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200);

    await expect(WPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("WPVCConfig fails gracefully on invalid response 2", async () => {
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: "OOPS",
      });

    await expect(WPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("WPVCConfig fails gracefully on invalid config", async () => {
    const config = {
      readme_incorrect: "path/to/readme.txt",
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(WPVCConfig()).rejects.toThrow(ConfigError);
  });
});
