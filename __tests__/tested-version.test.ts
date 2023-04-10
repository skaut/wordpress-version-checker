import * as core from "@actions/core";
import { mocked } from "jest-mock";
import mockedEnv from "mocked-env";
import nock from "nock";

import { InvalidReadmeError } from "../src/exceptions/InvalidReadmeError";
import { testedVersion } from "../src/tested-version";

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

  test.each([
    "Tested up to: 0.42",
    "Tested up to:0.42",
    "LINE1\nNot Tested up to: 0.41\nTested up to: 0.42\nLINE2",
    " Tested up to: 0.42",
    "    Tested up to: 0.42",
    "\tTested up to: 0.42",
    "\nTested up to: 0.42\n",
  ])("testedVersion works correctly", async (readme) => {
    expect.assertions(1);
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
      assignees: [],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(config)).resolves.toBe("0.42");
  });

  test("testedVersion works correctly with no config and readme.txt in repo root", async () => {
    expect.assertions(1);
    const readme = "Tested up to: 0.42";

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/readme.txt")
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(null)).resolves.toBe("0.42");
  });

  test("testedVersion works correctly with no config and readme.txt in the plugin folder", async () => {
    expect.assertions(1);
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

    await expect(testedVersion(null)).resolves.toBe("0.42");
  });

  test("testedVersion fails gracefully on connection issues", async () => {
    expect.assertions(1);
    const config = {
      readme: "path/to/readme.txt",
      assignees: [],
    };

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });

  test("testedVersion fails gracefully on no readme", async () => {
    expect.assertions(1);
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
      assignees: [],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(404);

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });

  test("testedVersion fails gracefully on invalid response", async () => {
    expect.assertions(1);
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
      assignees: [],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200);

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });

  test("testedVersion fails gracefully on invalid response 2", async () => {
    expect.assertions(1);
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
      assignees: [],
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
    expect.assertions(1);
    const readmePath = "path/to/readme.txt";
    const config = {
      readme: readmePath,
      assignees: [],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/" + encodeURIComponent(readmePath))
      .reply(200, {
        content: Buffer.from(readme).toString("base64"),
      });

    await expect(testedVersion(config)).rejects.toThrow(InvalidReadmeError);
  });
});
