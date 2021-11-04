import * as github from "@actions/github";

interface Repo {
  owner: string;
  repo: string;
}

export function repo(): Repo {
  return github.context.repo;
}
