import { compare } from "compare-versions";

import { ExistingIssueFormatError } from "./exceptions/ExistingIssueFormatError";
import { GetIssueError } from "./exceptions/GetIssueError";
import { IssueCommentError } from "./exceptions/IssueCommentError";
import { IssueCreationError } from "./exceptions/IssueCreationError";
import { IssueListError } from "./exceptions/IssueListError";
import { IssueUpdateError } from "./exceptions/IssueUpdateError";
import { octokit } from "./octokit";
import { repo } from "./repo";

function issueBody(testedVersion: string, latestVersion: string): string {
  return (
    'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n' +
    "\n" +
    "**Tested up to:** " +
    testedVersion +
    "\n" +
    "**Latest version:** " +
    latestVersion +
    "\n" +
    "\n" +
    "This issue will be closed automatically when the versions match."
  );
}

export async function getIssue(): Promise<number | null> {
  const issues = await octokit()
    .rest.issues.listForRepo({
      ...repo(),
      creator: "github-actions[bot]",
      labels: "wpvc",
    })
    .catch(function (e): never {
      throw new IssueListError(String(e));
    });
  return issues.data.length > 0 ? issues.data[0].number : null;
}

export async function commentOnIssue(
  issue: number,
  comment: string
): Promise<void> {
  await octokit()
    .rest.issues.createComment({
      ...repo(),
      issue_number: issue,
      body: comment,
    })
    .catch(function (e): never {
      throw new IssueCommentError(issue, String(e));
    });
}

export async function closeIssue(issue: number): Promise<void> {
  await octokit()
    .rest.issues.update({
      ...repo(),
      issue_number: issue,
      state: "closed",
    })
    .catch(function (e): never {
      throw new IssueUpdateError(issue, String(e));
    });
}

export async function createIssue(
  title: string,
  body: string,
  assignees: Array<string>
): Promise<void> {
  await octokit()
    .rest.issues.create({
      ...repo(),
      title,
      body,
      labels: ["wpvc"],
      assignees,
    })
    .catch(function (e): never {
      throw new IssueCreationError(String(e));
    });
}

export async function updateIssue(
  issueNumber: number,
  testedVersion: string,
  latestVersion: string
): Promise<void> {
  const issue = await octokit()
    .rest.issues.get({ ...repo(), issue_number: issueNumber })
    .catch(function (e): never {
      throw new GetIssueError(issueNumber, String(e));
    });
  if (issue.data.body === undefined || issue.data.body === null) {
    throw new ExistingIssueFormatError(issueNumber);
  }
  const matchingLine = issue.data.body.split("\r\n").find(function (line) {
    return line.startsWith("**Latest version:**");
  });
  if (matchingLine === undefined) {
    throw new ExistingIssueFormatError(issueNumber);
  }
  const latestVersionInIssue = matchingLine.slice(20);
  if (compare(latestVersionInIssue, latestVersion, "<")) {
    await octokit()
      .rest.issues.update({
        ...repo(),
        issue_number: issueNumber,
        body: issueBody(testedVersion, latestVersion),
      })
      .catch(function (e): never {
        throw new IssueUpdateError(issueNumber, String(e));
      });
  }
}
