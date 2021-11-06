//import nock from "nock";
import { mocked } from "ts-jest/utils";
//import mockedEnv from "mocked-env";

import { createIssue, getIssue, updateIssue } from "../src/issue-management";
import { latestWordPressVersion } from "../src/latest-version";
import { testedVersion } from "../src/tested-version";
import { WPVCConfig } from "../src/wpvc-config";
import { run } from "../src/run";

jest.mock("../src/issue-management");
jest.mock("../src/latest-version");
jest.mock("../src/tested-version");
jest.mock("../src/wpvc-config");

describe("[env variable mock]", () => {
  //let restore: () => void;

  beforeEach(() => {
    //restore = mockedEnv({ GITHUB_REPOSITORY: "OWNER/REPO" });
    //mocked(core).getInput.mockReturnValue("GH_TOKEN");
  });
  afterEach(() => {
    //restore();
  });

  test("run works correctly with outdated version and no existing issue", async () => {
    const config = { readme: "readme.txt" };
    const testedVersionValue = "0.41";
    const latestVersionValue = "0.42";

    mocked(createIssue).mockResolvedValue(undefined);
    mocked(getIssue).mockResolvedValue(null);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);
    await run();

    expect(mocked(createIssue).mock.calls.length).toBe(1);
    expect(mocked(createIssue).mock.calls[0][0]).toStrictEqual(config);
    expect(mocked(createIssue).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(createIssue).mock.calls[0][2]).toBe(latestVersionValue);
  });

  test("run works correctly with outdated version and an existing issue", async () => {
    const config = { readme: "readme.txt" };
    const testedVersionValue = "0.41";
    const latestVersionValue = "0.42";
    const existingIssue = 123;

    mocked(updateIssue).mockResolvedValue(undefined);
    mocked(getIssue).mockResolvedValue(existingIssue);
    mocked(latestWordPressVersion).mockResolvedValue(latestVersionValue);
    mocked(testedVersion).mockResolvedValue(testedVersionValue);
    mocked(WPVCConfig).mockResolvedValue(config);
    await run();

    expect(mocked(updateIssue).mock.calls.length).toBe(1);
    expect(mocked(updateIssue).mock.calls[0][0]).toBe(existingIssue);
    expect(mocked(updateIssue).mock.calls[0][1]).toBe(testedVersionValue);
    expect(mocked(updateIssue).mock.calls[0][2]).toBe(latestVersionValue);
  });
});
