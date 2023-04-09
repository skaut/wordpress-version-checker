import * as core from "@actions/core";
import { mocked } from "jest-mock";

//import { getIssue } from "../src/issue-management";
import { run } from "../src/run";
//import { testedVersion } from "../src/tested-version";
//import { wordpressVersions } from "../src/wordpress-versions";
import { WPVCConfig } from "../src/wpvc-config";

jest.mock("@actions/core");
jest.mock("../src/issue-management");
jest.mock("../src/tested-version");
jest.mock("../src/wordpress-versions");
jest.mock("../src/wpvc-config");

test("run fails gracefully on error", async () => {
  expect.assertions(1);
  mocked(WPVCConfig).mockImplementationOnce(() => {
    throw new Error();
  });

  await run();

  expect(mocked(core).setFailed.mock.calls).toHaveLength(1);
});
