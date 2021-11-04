import * as github from "@actions/github";

interface Repo {
  owner: string;
  repo: string;
}

let repoInstance: Repo | undefined = undefined;

export function repo(): Repo {
  if (repoInstance === undefined) {
    repoInstance = github.context.repo;
  }
  return repoInstance;
}
