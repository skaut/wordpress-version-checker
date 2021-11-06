import { createActionAuth } from "@octokit/auth-action";
import { Octokit } from "octokit";

let octokitInstance: Octokit | undefined = undefined;

export function octokit(): Octokit {
  if (octokitInstance === undefined) {
    octokitInstance = new Octokit({ authStrategy: createActionAuth });
  }
  return octokitInstance;
}
