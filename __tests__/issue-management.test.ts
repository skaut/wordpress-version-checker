import nock from "nock";
import { mocked } from "jest-mock";
import mockedEnv from "mocked-env";

import * as core from "@actions/core";

import {
  closeIssue,
  createIssue,
  getIssue,
  updateIssue,
} from "../src/issue-management";

import { ExistingIssueFormatError } from "../src/exceptions/ExistingIssueFormatError";
import { GetIssueError } from "../src/exceptions/GetIssueError";
import { IssueCreationError } from "../src/exceptions/IssueCreationError";
import { IssueListError } from "../src/exceptions/IssueListError";
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

  test("getIssue works correctly", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues")
      .query({ creator: "github-actions[bot]", labels: "wpvc" })
      .reply(200, [{ number: 123 }]);

    await expect(getIssue()).resolves.toBe(123);
  });

  test("getIssue works correctly when the issue doesn't exist", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues")
      .query({ creator: "github-actions[bot]", labels: "wpvc" })
      .reply(200, []);

    await expect(getIssue()).resolves.toBeNull();
  });

  test("getIssue fails gracefully on connection issues", async () => {
    expect.assertions(1);
    await expect(getIssue()).rejects.toThrow(IssueListError);
  });

  test("getIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues")
      .query({ creator: "github-actions[bot]", labels: "wpvc" })
      .reply(404);

    await expect(getIssue()).rejects.toThrow(IssueListError);
  });

  test("closeIssue works correctly", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .patch("/repos/OWNER/REPO/issues/123", {
        state: "closed",
      })
      .reply(200);

    await expect(closeIssue(123)).resolves.toBeUndefined();
  });

  test("closeIssue fails gracefully on connection issues", async () => {
    expect.assertions(1);
    await expect(closeIssue(123)).rejects.toThrow(IssueUpdateError);
  });

  test("closeIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .patch("/repos/OWNER/REPO/issues/123", {
        state: "closed",
      })
      .reply(404);

    await expect(closeIssue(123)).rejects.toThrow(IssueUpdateError);
  });

  test("createIssue works correctly", async () => {
    expect.assertions(2);
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
    expect(scope.isDone()).toBe(true);
  });

  test("createIssue works correctly with assignees", async () => {
    expect.assertions(2);
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
    expect(scope.isDone()).toBe(true);
  });

  test("createIssue works correctly with no config", async () => {
    expect.assertions(2);
    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues", {
        title:
          "The plugin hasn't been tested with the latest version of WordPress",
        body: /.*/g,
        labels: ["wpvc"],
      })
      .reply(201);

    await expect(createIssue(null, "0.41", "0.42")).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("createIssue fails gracefully on connection issues", async () => {
    expect.assertions(1);
    await expect(createIssue(null, "0.41", "0.42")).rejects.toThrow(
      IssueCreationError
    );
  });

  test("createIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(1);
    nock("https://api.github.com").post("/repos/OWNER/REPO/issues").reply(404);

    await expect(createIssue(null, "0.41", "0.42")).rejects.toThrow(
      IssueCreationError
    );
  });

  test("updateIssue works correctly", async () => {
    expect.assertions(2);
    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest version:** 0.42" })
      .patch("/repos/OWNER/REPO/issues/123")
      .reply(200);

    await expect(updateIssue(123, "0.41", "0.43")).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("updateIssue correctly does not update the issue if it isn't needed", async () => {
    expect.assertions(2);
    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest version:** 0.42" });

    await expect(updateIssue(123, "0.41", "0.42")).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("updateIssue fails gracefully on connection issues on getting the existing issue", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .patch("/repos/OWNER/REPO/issues/123")
      .reply(200);

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      GetIssueError
    );
  });

  test("updateIssue fails gracefully on connection issues on updating the existing issue", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest version:** 0.42" });

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      IssueUpdateError
    );
  });

  test("updateIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(1);
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
    expect.assertions(1);
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, {});

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      ExistingIssueFormatError
    );
  });

  test("updateIssue fails gracefully on malformed issue 2", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { body: "**Latest NOT version:** 0.42" });

    await expect(updateIssue(123, "0.41", "0.43")).rejects.toThrow(
      ExistingIssueFormatError
    );
  });
});
