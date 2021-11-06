import * as core from "@actions/core";
import * as github from "@actions/github";
import type { Octokit } from "@octokit/core";
import type { Api } from "@octokit/plugin-rest-endpoint-methods/dist-types/types";
import type { PaginateInterface } from "@octokit/plugin-paginate-rest";

type GitHub = Api & Octokit & { paginate: PaginateInterface };
let octokitInstance: GitHub | undefined = undefined;

export function octokit(): GitHub {
  if (octokitInstance === undefined) {
    octokitInstance = github.getOctokit(core.getInput("repo-token"));
  }
  return octokitInstance;
}
