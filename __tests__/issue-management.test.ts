import mockedEnv from "mocked-env";
import nock from "nock";

import { GetIssueError } from "../src/exceptions/GetIssueError";
import { IssueCommentError } from "../src/exceptions/IssueCommentError";
import { IssueCreationError } from "../src/exceptions/IssueCreationError";
import { IssueListError } from "../src/exceptions/IssueListError";
import { IssueUpdateError } from "../src/exceptions/IssueUpdateError";
import {
  closeIssue,
  commentOnIssue,
  createIssue,
  getIssue,
  updateIssue,
} from "../src/issue-management";

jest.mock("@actions/core");

describe("[env variable mock]", () => {
  let restore: () => void;

  beforeEach(() => {
    restore = mockedEnv({ GITHUB_REPOSITORY: "OWNER/REPO" });
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

  test("commentOnIssue works correctly", async () => {
    expect.assertions(2);
    const issueBody = "ISSUE_BODY";

    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues/123/comments", {
        body: issueBody,
      })
      .reply(200);

    await expect(commentOnIssue(123, issueBody)).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("commentOnIssue fails gracefully on connection issues", async () => {
    expect.assertions(1);
    await expect(commentOnIssue(123, "ISSUE_BODY")).rejects.toThrow(
      IssueCommentError,
    );
  });

  test("commentOnIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(2);
    const issueBody = "ISSUE_BODY";

    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues/123/comments", {
        body: issueBody,
      })
      .reply(404);

    await expect(commentOnIssue(123, issueBody)).rejects.toThrow(
      IssueCommentError,
    );
    expect(scope.isDone()).toBe(true);
  });

  test("closeIssue works correctly", async () => {
    expect.assertions(2);
    const scope = nock("https://api.github.com")
      .patch("/repos/OWNER/REPO/issues/123", {
        state: "closed",
      })
      .reply(200);

    await expect(closeIssue(123)).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("closeIssue fails gracefully on connection issues", async () => {
    expect.assertions(1);
    await expect(closeIssue(123)).rejects.toThrow(IssueUpdateError);
  });

  test("closeIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(2);
    const scope = nock("https://api.github.com")
      .patch("/repos/OWNER/REPO/issues/123", {
        state: "closed",
      })
      .reply(404);

    await expect(closeIssue(123)).rejects.toThrow(IssueUpdateError);
    expect(scope.isDone()).toBe(true);
  });

  test("createIssue works correctly", async () => {
    expect.assertions(2);
    const title = "ISSUE_TITLE";
    const body = "ISSUE_BODY";
    const assignees: Array<string> = [];

    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues", {
        title,
        body,
        labels: ["wpvc"],
        assignees,
      })
      .reply(201);

    await expect(createIssue(title, body, assignees)).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("createIssue works correctly with assignees", async () => {
    expect.assertions(2);
    const title = "ISSUE_TITLE";
    const body = "ISSUE_BODY";
    const assignees = ["PERSON1", "PERSON2"];

    const scope = nock("https://api.github.com")
      .post("/repos/OWNER/REPO/issues", {
        title,
        body,
        labels: ["wpvc"],
        assignees,
      })
      .reply(201);

    await expect(createIssue(title, body, assignees)).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("createIssue fails gracefully on connection issues", async () => {
    expect.assertions(1);

    await expect(createIssue("ISSUE_TITLE", "ISSUE_BODY", [])).rejects.toThrow(
      IssueCreationError,
    );
  });

  test("createIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(1);

    nock("https://api.github.com").post("/repos/OWNER/REPO/issues").reply(404);

    await expect(createIssue("ISSUE_TITLE", "ISSUE_BODY", [])).rejects.toThrow(
      IssueCreationError,
    );
  });

  test("updateIssue works correctly with an up-to-date-issue", async () => {
    expect.assertions(2);
    const title = "ISSUE_TITLE";
    const body = "ISSUE_BODY";

    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { title, body });
    //.patch("/repos/OWNER/REPO/issues/123")
    //.reply(200);

    await expect(updateIssue(123, title, body)).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("updateIssue works correctly with an issue with outdated title", async () => {
    expect.assertions(2);
    const title = "ISSUE_TITLE";
    const body = "ISSUE_BODY";

    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { title: "WRONG_TITLE", body })
      .patch("/repos/OWNER/REPO/issues/123", { title, body })
      .reply(200);

    await expect(updateIssue(123, title, body)).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("updateIssue works correctly with an issue with outdated body", async () => {
    expect.assertions(2);
    const title = "ISSUE_TITLE";
    const body = "ISSUE_BODY";

    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { title, body: "WRONG_BODY" })
      .patch("/repos/OWNER/REPO/issues/123", { title, body })
      .reply(200);

    await expect(updateIssue(123, title, body)).resolves.toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });

  test("updateIssue fails gracefully on connection issues on getting the existing issue", async () => {
    expect.assertions(1);
    const title = "ISSUE_TITLE";
    const body = "ISSUE_BODY";

    nock("https://api.github.com")
      .patch("/repos/OWNER/REPO/issues/123", { title, body })
      .reply(200);

    await expect(updateIssue(123, title, body)).rejects.toThrow(GetIssueError);
  });

  test("updateIssue fails gracefully on connection issues on updating the existing issue", async () => {
    expect.assertions(2);
    const title = "ISSUE_TITLE";
    const body = "ISSUE_BODY";

    const scope = nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(200, { title: "WRONG_TITLE", body });

    await expect(updateIssue(123, title, body)).rejects.toThrow(
      IssueUpdateError,
    );
    expect(scope.isDone()).toBe(true);
  });

  test("updateIssue fails gracefully on nonexistent repo", async () => {
    expect.assertions(1);
    nock("https://api.github.com")
      .get("/repos/OWNER/REPO/issues/123")
      .reply(404)
      .patch("/repos/OWNER/REPO/issues/123")
      .reply(404);

    await expect(updateIssue(123, "ISSUE_TITLE", "ISSUE_BODY")).rejects.toThrow(
      GetIssueError,
    );
  });
});
