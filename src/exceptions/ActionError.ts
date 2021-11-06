import { WPVCError } from "./WPVCError";

export class ActionError extends WPVCError {
  public constructor(e: string) {
    super(
      "Couldn't run the wordpress-version-checker action. Error message: " + e
    );
  }
}
