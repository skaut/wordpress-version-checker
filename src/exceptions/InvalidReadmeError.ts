import { WPVCError } from "./WPVCError";

export class InvalidReadmeError extends WPVCError {
  public constructor() {
    super("The repository has an invalid readme.");
  }
}
