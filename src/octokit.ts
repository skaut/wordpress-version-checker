import type { Octokit } from "@octokit/core";
import type { PaginateInterface } from "@octokit/plugin-paginate-rest";
import type { Api } from "@octokit/plugin-rest-endpoint-methods";

import * as core from "@actions/core";
import * as github from "@actions/github";

type GitHub = Api & Octokit & { paginate: PaginateInterface };
let octokitInstance: GitHub | undefined = undefined;

export function octokit(): GitHub {
  octokitInstance ??= github.getOctokit(core.getInput("repo-token"));
  return octokitInstance;
}
