import { Octokit } from "@octokit/action";

let octokitInstance: Octokit | undefined = undefined;

export function octokit(): Octokit {
  if (octokitInstance === undefined) {
    octokitInstance = new Octokit();
  }
  return octokitInstance;
}
