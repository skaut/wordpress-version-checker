import { mocked } from "jest-mock";

import { createIssue, updateIssue } from "../src/issue-management";
import { outdatedStable } from "../src/outdated-stable";

jest.mock("../src/issue-management");

describe("Succesful runs", () => {
  beforeEach(() => {
    mocked(createIssue).mockResolvedValue(undefined);
    mocked(updateIssue).mockResolvedValue(undefined);
  });

  test("run works correctly with outdated version and no existing issue", async () => {
    expect.assertions(5);
    const config = { readme: "readme.txt", assignees: [] };
    const testedVersion = "0.41";
    const latestVersion = "0.42";

    await outdatedStable(config, testedVersion, latestVersion, null);

    expect(mocked(createIssue).mock.calls).toHaveLength(1);
    expect(mocked(createIssue).mock.calls[0][0]).toStrictEqual(config);
    expect(mocked(createIssue).mock.calls[0][1]).toBe(testedVersion);
    expect(mocked(createIssue).mock.calls[0][2]).toBe(latestVersion);
    expect(mocked(updateIssue).mock.calls).toHaveLength(0);
  });

  test("run works correctly with outdated version and an existing issue", async () => {
    expect.assertions(5);
    const config = { readme: "readme.txt", assignees: [] };
    const testedVersion = "0.41";
    const latestVersion = "0.42";
    const existingIssue = 123;

    await outdatedStable(config, testedVersion, latestVersion, existingIssue);

    expect(mocked(createIssue).mock.calls).toHaveLength(0);
    expect(mocked(updateIssue).mock.calls).toHaveLength(1);
    expect(mocked(updateIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(mocked(updateIssue).mock.calls[0][1]).toBe(testedVersion);
    expect(mocked(updateIssue).mock.calls[0][2]).toBe(latestVersion);
  });
});
