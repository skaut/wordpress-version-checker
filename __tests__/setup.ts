import core from "@actions/core";
import github from "@actions/github";
import type { Octokit } from "@octokit/core";
import type { PaginateInterface } from "@octokit/plugin-paginate-rest";
import type { Api } from "@octokit/plugin-rest-endpoint-methods/dist-types/types";
import nock from "nock";
import nodeFetch from "node-fetch";

nock.disableNetConnect();

type GitHub = Api & Octokit & { paginate: PaginateInterface };

jest.mock("../src/octokit", () => ({
  octokit: (): GitHub =>
    github.getOctokit(core.getInput("repo-token"), {
      request: {
        fetch: nodeFetch,
      },
    }),
}));
