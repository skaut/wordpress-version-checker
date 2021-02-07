import { WPVCError } from "./WPVCError";

export class IssueListError extends WPVCError {
  public constructor(e: string) {
    super("Couldn't list issues. Error message: " + e);
  }
}
