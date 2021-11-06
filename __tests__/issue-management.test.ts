import nock from "nock";
import { mocked } from "ts-jest/utils";
import mockedEnv from "mocked-env";

import * as core from "@actions/core";

import { createIssue, updateIssue } from "../src/issue-management";

import { ExistingIssueFormatError } from "../src/exceptions/ExistingIssueFormatError";
import { GetIssueError } from "../src/exceptions/GetIssueError";
import { IssueCreationError } from "../src/exceptions/IssueCreationError";
import { IssueUpdateError } from "../src/exceptions/IssueUpdateError";

jest.mock("@actions/core");

describe("[env variable mock]", () => {
  let restore: () => void;

  beforeEach(() => {
    restore = mockedEnv({ GITHUB_REPOSITORY: "OWNER/REPO" });
    mocked(core).getInput.mockReturnValue("GH_TOKEN");
  });
  afterEach(() => {
    restore();
    nock.cleanAll();
  });

  test("createIssue works correctly", async () => {
    const config = {
      readme: "readme.txt",
    };

    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues", {
        title:
          "The plugin hasn't been tested with the latest version of WordPress",
        body: /.*/g,
        labels: ["wpvc"],
      })
      .reply(201);

    await expect(createIssue(config, "0.41", "0.42")).resolves.toBeUndefined();
    expect(scope.isDone()).toEqual(true);
  });

  test("createIssue works correctly with assignees", async () => {
    const config = {
      readme: "readme.txt",
      assignees: ["PERSON1", "PERSON2"],
    };

    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues", {
        title:
          "The plugin hasn't been tested with the latest version of WordPress",
        body: /.*/g,
        labels: ["wpvc"],
        assignees: ["PERSON1", "PERSON2"],
      })
      .reply(201);

    await expect(createIssue(config, "0.41", "0.42")).resolves.toBeUndefined();
    expect(scope.isDone()).toEqual(true);
  });

  test("createIssue works correctly with no config", async () => {
    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues", {
        title:
          "The plugin hasn't been tested with the latest version of WordPress",
        body: /.*/g,
        labels: ["wpvc"],
      })
      .reply(201);

    await expect(createIssue(null, "0.41", "0.42")).resolves.toBeUndefined();
    expect(scope.isDone()).toEqual(true);
  });

  test("createIssue fails gracefully on connection issues", async () => {
    await expect(createIssue(null, "0.41", "0.42")).rejects.toThrow(
      IssueCreationError
    );
  });

  test("createIssue fails gracefully on nonexistent repo", async () => {
    nock("https://api.github.com").post("/repos/OWNER/REPO/issues").reply(404);

    await expect(createIssue(null, "0.41", "0.42")).rejects.toThrow(
      IssueCreationError
    );
  });

  test("updateIssue works correctly", async () => {
    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest version:** 0.42" })
      .patch("/repos/OWNER/REPO/issues/123")
      .reply(200);

    await expect(updateIssue(123, "0.41", "0.43")).resolves.toBeUndefined();
    expect(scope.isDone()).toEqual(true);
  });

  test("updateIssue correctly does not update the issue if it isn't needed", async () => {
    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest version:** 0.42" });

    await expect(updateIssue(123, "0.41", "0.42")).resolves.toBeUndefined();
    expect(scope.isDone()).toEqual(true);
  });

  test("updateIssue fails gracefully on connection issues on getting the existing issue", async () => {
    nock("https://api.github.com")
      .patch("/repos/OWNER/REPO/issues/123")
      .reply(200);

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      GetIssueError
    );
  });

  test("updateIssue fails gracefully on connection issues on updating the existing issue", async () => {
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest version:** 0.42" });

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      IssueUpdateError
    );
  });

  test("updateIssue fails gracefully on nonexistent repo", async () => {
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(404)
      .patch("/repos/OWNER/REPO/issues/123")
      .reply(404);

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      GetIssueError
    );
  });

  test("updateIssue fails gracefully on malformed issue 1", async () => {
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, {});

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      ExistingIssueFormatError
    );
  });

  test("updateIssue fails gracefully on malformed issue 2", async () => {
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest NOT version:** 0.42" });

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      ExistingIssueFormatError
    );
  });
});
