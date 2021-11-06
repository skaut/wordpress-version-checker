import { ActionError } from "./exceptions/ActionError";

interface Repo {
  owner: string;
  repo: string;
}

let repoInstance: Repo | undefined = undefined;

export function repo(): Repo {
  if (repoInstance === undefined) {
    if (process.env.GITHUB_REPOSITORY === undefined) {
      throw new ActionError(
        'No "GITHUB_REPOSITORY" environment variable found'
      );
    }
    const split = process.env.GITHUB_REPOSITORY.split("/");
    if (split.length !== 2) {
      throw new ActionError(
        'The "GITHUB_REPOSITORY" environment variable is not in the correct format'
      );
    }
    repoInstance = {
      owner: split[0],
      repo: split[1],
    };
  }
  return repoInstance;
}
