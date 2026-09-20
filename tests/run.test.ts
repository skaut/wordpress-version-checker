import * as core from "@actions/core";
import { beforeEach, describe, expect, test, vi } from "vitest";

import type { Config } from "../src/interfaces/Config";

import { outdatedBeta } from "../src/outdated-beta";
import { outdatedRC } from "../src/outdated-rc";
import { outdatedStable } from "../src/outdated-stable";
import { run } from "../src/run";
import { testedVersion } from "../src/tested-version";
import { upToDate } from "../src/up-to-date";
import { wordpressVersions } from "../src/wordpress-versions";
import { getWPVCConfig } from "../src/wpvc-config";

vi.mock("@actions/core");
vi.mock("../src/outdated-beta");
vi.mock("../src/outdated-rc");
vi.mock("../src/outdated-stable");
vi.mock("../src/tested-version");
vi.mock("../src/up-to-date");
vi.mock("../src/wordpress-versions");
vi.mock("../src/wpvc-config");

describe("runs succesfully", () => {
  beforeEach(() => {
    vi.mocked(outdatedBeta).mockResolvedValue();
    vi.mocked(outdatedRC).mockResolvedValue();
    vi.mocked(outdatedStable).mockResolvedValue();
    vi.mocked(upToDate).mockResolvedValue();
  });

  test("works with stable channel and up-to-date version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "stable",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.42", rc: "0.42", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with stable channel and newer beta version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "stable",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.42", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with stable channel and newer RC version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "stable",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with stable channel and newer stable version", async () => {
    expect.assertions(7);

    const config: Config = {
      assignees: [],
      channel: "stable",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.43" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(1);
    expect(vi.mocked(outdatedStable).mock.calls[0][0]).toStrictEqual(config);
    expect(vi.mocked(outdatedStable).mock.calls[0][1]).toBe(testedVersionValue);
    expect(vi.mocked(outdatedStable).mock.calls[0][2]).toBe(
      wordpressVersionsValue.stable,
    );
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with RC channel and up-to-date version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "rc",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.42", rc: "0.42", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with RC channel and newer beta version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "rc",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.42", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with RC channel and newer RC version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "rc",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(1);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with RC channel and newer stable version", async () => {
    expect.assertions(7);

    const config: Config = {
      assignees: [],
      channel: "rc",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.43" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(1);
    expect(vi.mocked(outdatedStable).mock.calls[0][0]).toStrictEqual(config);
    expect(vi.mocked(outdatedStable).mock.calls[0][1]).toBe(testedVersionValue);
    expect(vi.mocked(outdatedStable).mock.calls[0][2]).toBe(
      wordpressVersionsValue.stable,
    );
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with beta channel and up-to-date version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "beta",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.42", rc: "0.42", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with beta channel and newer beta version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "beta",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.42", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(1);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with beta channel and newer RC version", async () => {
    expect.assertions(4);

    const config: Config = {
      assignees: [],
      channel: "beta",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.42" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(1);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with beta channel and newer stable version", async () => {
    expect.assertions(7);

    const config: Config = {
      assignees: [],
      channel: "beta",
      readme: ["readme.txt"],
    };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.43" };

    vi.mocked(getWPVCConfig).mockResolvedValue(config);
    vi.mocked(testedVersion).mockResolvedValue(testedVersionValue);
    vi.mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(vi.mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(vi.mocked(outdatedStable).mock.calls).toHaveLength(1);
    expect(vi.mocked(outdatedStable).mock.calls[0][0]).toStrictEqual(config);
    expect(vi.mocked(outdatedStable).mock.calls[0][1]).toBe(testedVersionValue);
    expect(vi.mocked(outdatedStable).mock.calls[0][2]).toBe(
      wordpressVersionsValue.stable,
    );
    expect(vi.mocked(upToDate).mock.calls).toHaveLength(0);
  });
});

test("run fails gracefully on error", async () => {
  expect.assertions(1);

  vi.mocked(getWPVCConfig).mockImplementationOnce(() => {
    throw new Error();
  });

  await run();

  expect(vi.mocked(core).setFailed.mock.calls).toHaveLength(1);
});
