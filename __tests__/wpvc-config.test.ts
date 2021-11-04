import nock from "nock";
import { mocked } from "ts-jest/utils";
import mockedEnv from "mocked-env";

import * as core from "@actions/core";

import { WPVCConfig } from "../src/wpvc-config";

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
});
