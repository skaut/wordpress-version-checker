import { mocked } from "jest-mock";

import type { Config } from "../src/interfaces/Config";

import { createIssue, getIssue, updateIssue } from "../src/issue-management";
import { outdatedBeta } from "../src/outdated-beta";

jest.mock("../src/issue-management");

describe("Succesful runs", () => {
  beforeEach(() => {
    mocked(createIssue).mockResolvedValue(undefined);
    mocked(updateIssue).mockResolvedValue(undefined);
  });

  test("outdatedBeta works correctly with outdated version and no existing issue", async () => {
    expect.assertions(7);

    const config: Config = {
      assignees: [],
      channel: "beta",
      readme: ["readme.txt"],
    };
    const testedVersion = "0.41";
    const latestVersion = "0.42";

    mocked(getIssue).mockResolvedValue(null);

    await outdatedBeta(config, testedVersion, latestVersion);

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(createIssue).mock.calls).toHaveLength(1);
    expect(mocked(createIssue).mock.calls[0][0]).toBe(
      "The plugin hasn't been tested with a beta version of WordPress",
    );
    expect(mocked(createIssue).mock.calls[0][1]).toMatch(
      /\*\*Tested up to:\*\* 0\.41/gu,
    );
    expect(mocked(createIssue).mock.calls[0][1]).toMatch(
      /\*\*Beta version:\*\* 0\.42/gu,
    );
    expect(mocked(createIssue).mock.calls[0][2]).toStrictEqual([]);
    expect(mocked(updateIssue).mock.calls).toHaveLength(0);
  });

  test("outdatedBeta works correctly with outdated version and an existing issue", async () => {
    expect.assertions(7);

    const config: Config = {
      assignees: [],
      channel: "beta",
      readme: ["readme.txt"],
    };
    const testedVersion = "0.41";
    const latestVersion = "0.42";
    const existingIssue = 123;

    mocked(getIssue).mockResolvedValue(existingIssue);

    await outdatedBeta(config, testedVersion, latestVersion);

    expect(mocked(getIssue).mock.calls).toHaveLength(1);
    expect(mocked(createIssue).mock.calls).toHaveLength(0);
    expect(mocked(updateIssue).mock.calls).toHaveLength(1);
    expect(mocked(updateIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(mocked(updateIssue).mock.calls[0][1]).toBe(
      "The plugin hasn't been tested with a beta version of WordPress",
    );
    expect(mocked(updateIssue).mock.calls[0][2]).toMatch(
      /\*\*Tested up to:\*\* 0\.41/gu,
    );
    expect(mocked(updateIssue).mock.calls[0][2]).toMatch(
      /\*\*Beta version:\*\* 0\.42/gu,
    );
  });
});
