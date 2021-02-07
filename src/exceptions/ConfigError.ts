import { WPVCError } from "./WPVCError";

export class ConfigError extends WPVCError {
  public constructor(e: string) {
    super(
      "Couldn't get the wordpress-version-checker config file. Error message: " +
        e
    );
  }
}
