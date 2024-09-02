import type { Octokit } from "@octokit/core";
import type { PaginateInterface } from "@octokit/plugin-paginate-rest";
import type { Api } from "@octokit/plugin-rest-endpoint-methods/dist-types/types";

import * as core from "@actions/core";
import * as github from "@actions/github";

type GitHub = { paginate: PaginateInterface } & Api & Octokit;
let octokitInstance: GitHub | undefined = undefined;

export function octokit(): GitHub {
  if (octokitInstance === undefined) {
    octokitInstance = github.getOctokit(core.getInput("repo-token"));
  }
  return octokitInstance;
}
