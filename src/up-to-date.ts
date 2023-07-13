import { closeIssue, commentOnIssue, getIssue } from "./issue-management";

export async function upToDate(): Promise<void> {
  const existingIssue = await getIssue();
  if (existingIssue !== null) {
    await commentOnIssue(
      existingIssue,
      'The "Tested up to" version in the readme matches the latest version now, closing this issue.',
    );
    await closeIssue(existingIssue);
  }
}
