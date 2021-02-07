import { WPVCError } from "./WPVCError";

export class GetIssueError extends WPVCError {
  public constructor(issueNumber: number, e: string) {
    super(
      "Couldn't get the already existing issue #" +
        String(issueNumber) +
        ". Error message: " +
        e
    );
  }
}
