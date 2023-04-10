import * as core from "@actions/core";
import { mocked } from "jest-mock";

import type { Config } from "../src/interfaces/Config";
import { getIssue } from "../src/issue-management";
import { outdatedBeta } from "../src/outdated-beta";
import { outdatedRC } from "../src/outdated-rc";
import { outdatedStable } from "../src/outdated-stable";
import { run } from "../src/run";
import { testedVersion } from "../src/tested-version";
import { upToDate } from "../src/up-to-date";
import { wordpressVersions } from "../src/wordpress-versions";
import { WPVCConfig } from "../src/wpvc-config";

jest.mock("@actions/core");
jest.mock("../src/issue-management");
jest.mock("../src/outdated-beta");
jest.mock("../src/outdated-rc");
jest.mock("../src/outdated-stable");
jest.mock("../src/tested-version");
jest.mock("../src/up-to-date");
jest.mock("../src/wordpress-versions");
jest.mock("../src/wpvc-config");

describe("runs succesfully", () => {
  beforeEach(() => {
    mocked(getIssue).mockResolvedValue(123);
    mocked(outdatedBeta).mockReturnValue();
    mocked(outdatedRC).mockReturnValue();
    mocked(outdatedStable).mockResolvedValue();
    mocked(upToDate).mockResolvedValue();
  });

  test("works with stable channel and up-to-date version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "stable" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.42", rc: "0.42", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(0);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with stable channel and newer beta version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "stable" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.42", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(0);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with stable channel and newer RC version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "stable" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(0);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with stable channel and newer stable version", async () => {
    expect.assertions(9);
    const config: Config = { readme: "readme.txt", channel: "stable" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.43" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(1);
    expect(mocked(outdatedStable).mock.calls[0][0]).toStrictEqual(config);
    expect(mocked(outdatedStable).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(outdatedStable).mock.calls[0][2]).toBe(
      wordpressVersionsValue.stable
    );
    expect(mocked(outdatedStable).mock.calls[0][3]).toBe(123);
    expect(mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with RC channel and up-to-date version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "rc" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.42", rc: "0.42", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(0);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with RC channel and newer beta version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "rc" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.42", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(0);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with RC channel and newer RC version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "rc" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(1);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with RC channel and newer stable version", async () => {
    expect.assertions(9);
    const config: Config = { readme: "readme.txt", channel: "rc" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.43" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(1);
    expect(mocked(outdatedStable).mock.calls[0][0]).toStrictEqual(config);
    expect(mocked(outdatedStable).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(outdatedStable).mock.calls[0][2]).toBe(
      wordpressVersionsValue.stable
    );
    expect(mocked(outdatedStable).mock.calls[0][3]).toBe(123);
    expect(mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with beta channel and up-to-date version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "beta" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.42", rc: "0.42", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(0);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(1);
  });

  test("works with beta channel and newer beta version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "beta" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.42", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(1);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with beta channel and newer RC version", async () => {
    expect.assertions(5);
    const config: Config = { readme: "readme.txt", channel: "beta" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.42" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(1);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(0);
    expect(mocked(upToDate).mock.calls).toHaveLength(0);
  });

  test("works with beta channel and newer stable version", async () => {
    expect.assertions(9);
    const config: Config = { readme: "readme.txt", channel: "beta" };
    const testedVersionValue = "0.42";
    const wordpressVersionsValue = { beta: "0.43", rc: "0.43", stable: "0.43" };

    mocked(WPVCConfig).mockResolvedValue(config);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(wordpressVersions).mockResolvedValue(wordpressVersionsValue);

    await run();

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(outdatedBeta).mock.calls).toHaveLength(0);
    expect(mocked(outdatedRC).mock.calls).toHaveLength(0);
    expect(mocked(outdatedStable).mock.calls).toHaveLength(1);
    expect(mocked(outdatedStable).mock.calls[0][0]).toStrictEqual(config);
    expect(mocked(outdatedStable).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(outdatedStable).mock.calls[0][2]).toBe(
      wordpressVersionsValue.stable
    );
    expect(mocked(outdatedStable).mock.calls[0][3]).toBe(123);
    expect(mocked(upToDate).mock.calls).toHaveLength(0);
  });
});

test("run fails gracefully on error", async () => {
  expect.assertions(1);
  mocked(WPVCConfig).mockImplementationOnce(() => {
    throw new Error();
  });

  await run();

  expect(mocked(core).setFailed.mock.calls).toHaveLength(1);
});
