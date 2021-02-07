import { WPVCError } from "./WPVCError";

export class IssueCreationError extends WPVCError {
  public constructor(e: string) {
    super("Couldn't create an issue. Error message: " + e);
  }
}
