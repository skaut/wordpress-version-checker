import nock from "nock";
import { mocked } from "ts-jest/utils";
import mockedEnv from "mocked-env";

import * as core from "@actions/core";

import { testedVersion } from "../src/tested-version";

import { InvalidReadmeError } from "../src/exceptions/InvalidReadmeError";

jest.mock("@actions/core");

describe("[env variable mock]", () => {
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

  test("testedVersion works correctly with multi-line readme", async () => {
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
    };
    const readme = "LINE1\nNot Tested up to: 0.41\nTested up to: 0.42\nLINE2";

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(config)).resolves.toStrictEqual("0.42");
  });

  test("testedVersion works correctly with no config and readme.txt in repo root", async () => {
    const readme = "Tested up to: 0.42";

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/readme.txt")
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(null)).resolves.toStrictEqual("0.42");
  });

  test("testedVersion works correctly with no config and readme.txt in the plugin folder", async () => {
    const readme = "Tested up to: 0.42";

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/readme.txt")
      .reply(404);
    nock("https://api.github.com")
      .get(
        "/repos/OWNER/REPO/contents/" + encodeURIComponent("plugin/readme.txt")
      )
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(null)).resolves.toStrictEqual("0.42");
  });

  test("testedVersion fails gracefully on connection issues", async () => {
    const config = {
      readme: "path/to/readme.txt",
    };

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });

  test("testedVersion fails gracefully on no readme", async () => {
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(404);

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });

  test("testedVersion fails gracefully on invalid response", async () => {
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200);

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });

  test("testedVersion fails gracefully on invalid response 2", async () => {
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200, {
        content: "OOPS",
      });

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });

  test.each([
    "Not Tested up to: 0.42",
    "Tested up to:",
    "Tested up to: 0.42:",
    "Tested up to 0.42",
    "Tested up to 0.42:",
    "Tested up to: 0.41: 0.42",
  ])("testedVersion fails gracefully on invalid readme", async (readme) => {
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });
});
