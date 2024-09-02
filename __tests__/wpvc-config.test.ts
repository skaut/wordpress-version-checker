import mockedEnv from "mocked-env";
import nock from "nock";

import { ConfigError } from "../src/exceptions/ConfigError";
import { getWPVCConfig } from "../src/wpvc-config";

jest.mock("@actions/core");

describe("Mocked env variables", () => {
  // eslint-disable-next-line @typescript-eslint/init-declarations -- Shouldn't assign outside of hooks
  let restore: () => void;

  beforeEach(() => {
    restore = mockedEnv({ GITHUB_REPOSITORY: "OWNER/REPO" });
  });

  afterEach(() => {
    restore();
  });

  test("getWPVCConfig works correctly", async () => {
    expect.assertions(1);

    const config = {
      assignees: ["PERSON1", "PERSON2"],
      channel: "rc",
      readme: ["path/to/readme.txt"],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(getWPVCConfig()).resolves.toStrictEqual(config);
  });

  test("getWPVCConfig works correctly with a single readme", async () => {
    expect.assertions(1);

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(
          JSON.stringify({
            assignees: [],
            channel: "rc",
            readme: "path/to/readme.txt",
          }),
        ).toString("base64"),
      });

    await expect(getWPVCConfig()).resolves.toStrictEqual({
      assignees: [],
      channel: "rc",
      readme: ["path/to/readme.txt"],
    });
  });

  test("getWPVCConfig works correctly with empty config", async () => {
    expect.assertions(1);

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify({})).toString("base64"),
      });

    await expect(getWPVCConfig()).resolves.toStrictEqual({
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
    });
  });

  test("getWPVCConfig fails gracefully on connection issues", async () => {
    expect.assertions(1);
    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig returns defaults on no config", async () => {
    expect.assertions(1);

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(404);

    await expect(getWPVCConfig()).resolves.toStrictEqual({
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
    });
  });

  test("getWPVCConfig fails gracefully on invalid response", async () => {
    expect.assertions(1);

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200);

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid response 2", async () => {
    expect.assertions(1);

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: "OOPS",
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid config", async () => {
    expect.assertions(1);

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(false)).toString("base64"),
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid config 2", async () => {
    expect.assertions(1);

    const config = {
      readme: false,
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid config 3", async () => {
    expect.assertions(1);

    const config = {
      readme: ["readme.txt", false],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid config 4", async () => {
    expect.assertions(1);

    const config = {
      assignees: false,
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid config 5", async () => {
    expect.assertions(1);

    const config = {
      assignees: ["user", false],
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid config 6", async () => {
    expect.assertions(1);

    const config = {
      channel: false,
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });

  test("getWPVCConfig fails gracefully on invalid config 7", async () => {
    expect.assertions(1);

    const config = {
      channel: "not-stable",
    };

    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/contents/.wordpress-version-checker.json")
      .reply(200, {
        content: Buffer.from(JSON.stringify(config)).toString("base64"),
      });

    await expect(getWPVCConfig()).rejects.toThrow(ConfigError);
  });
});
