import { WPVCError } from "./WPVCError";

export class IssueUpdateError extends WPVCError {
  public constructor(issueNumber: number, e: string) {
    super(
      "Couldn't update the existing issue #" +
        String(issueNumber) +
        ". Error message: " +
        e
    );
  }
}
