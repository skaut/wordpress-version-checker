import nock from "nock";
import { mocked } from "ts-jest/utils";
import mockedEnv from "mocked-env";

import * as core from "@actions/core";

import { testedVersion } from "../src/tested-version";

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

  test("testedVersion works correctly", async () => {
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
    };
    const readme = "Tested up to: 0.42";

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(config)).resolves.toStrictEqual("0.42");
  });
});
