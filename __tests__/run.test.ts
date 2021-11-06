import { mocked } from "ts-jest/utils";
import * as core from "@actions/core";

import {
  closeIssue,
  createIssue,
  getIssue,
  updateIssue,
} from "../src/issue-management";
import { latestWordPressVersion } from "../src/latest-version";
import { testedVersion } from "../src/tested-version";
import { WPVCConfig } from "../src/wpvc-config";
import { run } from "../src/run";

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
    const config = { readme: "readme.txt" };
    const testedVersionValue = "0.41";
    const latestVersionValue = "0.42";

    mocked(getIssue).mockResolvedValue(null);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls.length).toBe(0);
    expect(mocked(createIssue).mock.calls.length).toBe(1);
    expect(mocked(createIssue).mock.calls[0][0]).toStrictEqual(config);
    expect(mocked(createIssue).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(createIssue).mock.calls[0][2]).toBe(latestVersionValue);
    expect(mocked(updateIssue).mock.calls.length).toBe(0);
  });

  test("run works correctly with outdated version and an existing issue", async () => {
    const config = { readme: "readme.txt" };
    const testedVersionValue = "0.41";
    const latestVersionValue = "0.42";
    const existingIssue = 123;

    mocked(getIssue).mockResolvedValue(existingIssue);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls.length).toBe(0);
    expect(mocked(createIssue).mock.calls.length).toBe(0);
    expect(mocked(updateIssue).mock.calls.length).toBe(1);
    expect(mocked(updateIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(mocked(updateIssue).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(updateIssue).mock.calls[0][2]).toBe(latestVersionValue);
  });

  test("run works correctly with up-to-date version and no existing issue", async () => {
    const config = { readme: "readme.txt" };
    const testedVersionValue = "0.42";
    const latestVersionValue = "0.42";

    mocked(getIssue).mockResolvedValue(null);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls.length).toBe(0);
    expect(mocked(createIssue).mock.calls.length).toBe(0);
    expect(mocked(updateIssue).mock.calls.length).toBe(0);
  });

  test("run works correctly with up-to-date version and an existing issue", async () => {
    const config = { readme: "readme.txt" };
    const testedVersionValue = "0.42";
    const latestVersionValue = "0.42";
    const existingIssue = 123;

    mocked(getIssue).mockResolvedValue(existingIssue);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);

    await run();

    expect(mocked(closeIssue).mock.calls.length).toBe(1);
    expect(mocked(closeIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(mocked(createIssue).mock.calls.length).toBe(0);
    expect(mocked(updateIssue).mock.calls.length).toBe(0);
  });
});

test("run fails gracefully on error", async () => {
  mocked(WPVCConfig).mockImplementationOnce(() => {
    throw new Error();
  });

  await run();

  expect(mocked(core).setFailed.mock.calls.length).toBe(1);
});
