import { beforeEach, describe, expect, test, vi } from "vitest";

import type { Config } from "../src/interfaces/Config";

import { createIssue, getIssue, updateIssue } from "../src/issue-management";
import { outdatedBeta } from "../src/outdated-beta";

vi.mock("../src/issue-management");

describe("Succesful runs", () => {
  beforeEach(() => {
    vi.mocked(createIssue).mockResolvedValue(undefined);
    vi.mocked(updateIssue).mockResolvedValue(undefined);
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

    vi.mocked(getIssue).mockResolvedValue(null);

    await outdatedBeta(config, testedVersion, latestVersion);

    expect(vi.mocked(getIssue).mock.calls).toHaveLength(1);
    expect(vi.mocked(createIssue).mock.calls).toHaveLength(1);
    expect(vi.mocked(createIssue).mock.calls[0][0]).toBe(
      "The plugin hasn't been tested with a beta version of WordPress",
    );
    expect(vi.mocked(createIssue).mock.calls[0][1]).toMatch(
      /\*\*Tested up to:\*\* 0\.41/gu,
    );
    expect(vi.mocked(createIssue).mock.calls[0][1]).toMatch(
      /\*\*Beta version:\*\* 0\.42/gu,
    );
    expect(vi.mocked(createIssue).mock.calls[0][2]).toStrictEqual([]);
    expect(vi.mocked(updateIssue).mock.calls).toHaveLength(0);
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

    vi.mocked(getIssue).mockResolvedValue(existingIssue);

    await outdatedBeta(config, testedVersion, latestVersion);

    expect(vi.mocked(getIssue).mock.calls).toHaveLength(1);
    expect(vi.mocked(createIssue).mock.calls).toHaveLength(0);
    expect(vi.mocked(updateIssue).mock.calls).toHaveLength(1);
    expect(vi.mocked(updateIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(vi.mocked(updateIssue).mock.calls[0][1]).toBe(
      "The plugin hasn't been tested with a beta version of WordPress",
    );
    expect(vi.mocked(updateIssue).mock.calls[0][2]).toMatch(
      /\*\*Tested up to:\*\* 0\.41/gu,
    );
    expect(vi.mocked(updateIssue).mock.calls[0][2]).toMatch(
      /\*\*Beta version:\*\* 0\.42/gu,
    );
  });
});
