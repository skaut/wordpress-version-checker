import { WPVCError } from "./WPVCError";

export class InvalidReadmeError extends WPVCError {
  public constructor(e: string) {
    super("Couldn't get the repository readme. Error message: " + e);
  }
}
