import * as core from "@actions/core";
import { mocked } from "jest-mock";

import {
  closeIssue,
  createIssue,
  getIssue,
  updateIssue,
} from "../src/issue-management";
import { latestWordPressVersion } from "../src/latest-version";
import { run } from "../src/run";
import { testedVersion } from "../src/tested-version";
import { WPVCConfig } from "../src/wpvc-config";

jest.mock("@actions/core");
jest.mock("../src/issue-management");
jest.mock("../src/latest-version");
jest.mock("../src/tested-version");
jest.mock("../src/wpvc-config");

describe("Succesful runs", () => {
  beforeEach(() => {
    mocked(closeIssue).mockResolvedValue(undefined);
    mocked(createIssue).mockResolvedValue(undefined);
    mocked(updateIssue).mockResolvedValue(undefined);
  });

  test("run works correctly with outdated version and no existing issue", async () => {
    expect.assertions(6);
    const config = { readme: "readme.txt", assignees: [] };
    const testedVersionValue = "0.41";
    const latestVersionValue = "0.42";

    mocked(getIssue).mockResolvedValue(null);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls).toHaveLength(0);
    expect(mocked(createIssue).mock.calls).toHaveLength(1);
    expect(mocked(createIssue).mock.calls[0][0]).toStrictEqual(config);
    expect(mocked(createIssue).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(createIssue).mock.calls[0][2]).toBe(latestVersionValue);
    expect(mocked(updateIssue).mock.calls).toHaveLength(0);
  });

  test("run works correctly with outdated version and an existing issue", async () => {
    expect.assertions(6);
    const config = { readme: "readme.txt", assignees: [] };
    const testedVersionValue = "0.41";
    const latestVersionValue = "0.42";
    const existingIssue = 123;

    mocked(getIssue).mockResolvedValue(existingIssue);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls).toHaveLength(0);
    expect(mocked(createIssue).mock.calls).toHaveLength(0);
    expect(mocked(updateIssue).mock.calls).toHaveLength(1);
    expect(mocked(updateIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(mocked(updateIssue).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(updateIssue).mock.calls[0][2]).toBe(latestVersionValue);
  });

  test("run works correctly with up-to-date version and no existing issue", async () => {
    expect.assertions(3);
    const config = { readme: "readme.txt", assignees: [] };
    const testedVersionValue = "0.42";
    const latestVersionValue = "0.42";

    mocked(getIssue).mockResolvedValue(null);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls).toHaveLength(0);
    expect(mocked(createIssue).mock.calls).toHaveLength(0);
    expect(mocked(updateIssue).mock.calls).toHaveLength(0);
  });

  test("run works correctly with up-to-date version and an existing issue", async () => {
    expect.assertions(4);
    const config = { readme: "readme.txt", assignees: [] };
    const testedVersionValue = "0.42";
    const latestVersionValue = "0.42";
    const existingIssue = 123;

    mocked(getIssue).mockResolvedValue(existingIssue);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls).toHaveLength(1);
    expect(mocked(closeIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(mocked(createIssue).mock.calls).toHaveLength(0);
    expect(mocked(updateIssue).mock.calls).toHaveLength(0);
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
