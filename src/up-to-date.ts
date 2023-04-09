import { closeIssue, getIssue } from "./issue-management";

export async function upToDate(): Promise<void> {
  const existingIssue = await getIssue();
  if (existingIssue !== null) {
    await closeIssue(existingIssue);
  }
}
