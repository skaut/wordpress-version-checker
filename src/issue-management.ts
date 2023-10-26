import { GetIssueError } from "./exceptions/GetIssueError";
import { IssueCommentError } from "./exceptions/IssueCommentError";
import { IssueCreationError } from "./exceptions/IssueCreationError";
import { IssueListError } from "./exceptions/IssueListError";
import { IssueUpdateError } from "./exceptions/IssueUpdateError";
import { octokit } from "./octokit";
import { repo } from "./repo";

export async function getIssue(): Promise<number | null> {
  const issues = await octokit()
    .rest.issues.listForRepo({
      ...repo(),
      creator: "github-actions[bot]",
      labels: "wpvc",
    })
    .catch((e): never => {
      throw new IssueListError(String(e));
    });
  return issues.data.length > 0 ? issues.data[0].number : null;
}

export async function commentOnIssue(
  issue: number,
  comment: string,
): Promise<void> {
  await octokit()
    .rest.issues.createComment({
      ...repo(),
      issue_number: issue,
      body: comment,
    })
    .catch((e): never => {
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
    .catch((e): never => {
      throw new IssueUpdateError(issue, String(e));
    });
}

export async function createIssue(
  title: string,
  body: string,
  assignees: Array<string>,
): Promise<void> {
  await octokit()
    .rest.issues.create({
      ...repo(),
      title,
      body,
      labels: ["wpvc"],
      assignees,
    })
    .catch((e): never => {
      throw new IssueCreationError(String(e));
    });
}

export async function updateIssue(
  issueNumber: number,
  title: string,
  body: string,
): Promise<void> {
  const issue = await octokit()
    .rest.issues.get({ ...repo(), issue_number: issueNumber })
    .catch((e): never => {
      throw new GetIssueError(issueNumber, String(e));
    });
  if (issue.data.title === title && issue.data.body === body) {
    return;
  }
  await octokit()
    .rest.issues.update({
      ...repo(),
      issue_number: issueNumber,
      title,
      body,
    })
    .catch((e): never => {
      throw new IssueUpdateError(issueNumber, String(e));
    });
}
