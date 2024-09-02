import { mocked } from "jest-mock";

import { closeIssue, getIssue } from "../src/issue-management";
import { upToDate } from "../src/up-to-date";

jest.mock("../src/issue-management");

describe("Succesful runs", () => {
  beforeEach(() => {
    mocked(closeIssue).mockResolvedValue(undefined);
  });

  test("run works correctly with up-to-date version and no existing issue", async () => {
    expect.assertions(1);

    mocked(getIssue).mockResolvedValue(null);

    await upToDate();

    expect(mocked(closeIssue).mock.calls).toHaveLength(0);
  });

  test("run works correctly with up-to-date version and an existing issue", async () => {
    expect.assertions(2);

    const existingIssue = 123;

    mocked(getIssue).mockResolvedValue(existingIssue);

    await upToDate();

    expect(mocked(closeIssue).mock.calls).toHaveLength(1);
    expect(mocked(closeIssue).mock.calls[0][0]).toBe(existingIssue);
  });
});
