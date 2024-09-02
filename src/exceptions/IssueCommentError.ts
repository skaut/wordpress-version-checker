import { WPVCError } from "./WPVCError";

export class IssueCommentError extends WPVCError {
  public constructor(issueNumber: number, e: string) {
    super(
      `Couldn't add a comment to issue #${String(issueNumber)}. Error message: ${e}`,
    );
  }
}
