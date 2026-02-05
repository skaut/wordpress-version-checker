import type { Octokit } from "@octokit/core";
import type { PaginateInterface } from "@octokit/plugin-paginate-rest";
import type { Api } from "@octokit/plugin-rest-endpoint-methods";

import * as github from "@actions/github";
import nock from "nock";
import nodeFetch from "node-fetch";
import { vi } from "vitest";

/* eslint-disable vitest/require-hook -- OK in the setup file */

nock.disableNetConnect();

type GitHub = Api & Octokit & { paginate: PaginateInterface };

vi.mock("../src/octokit", () => ({
  octokit: (): GitHub =>
    github.getOctokit("GH_TOKEN", {
      request: {
        fetch: nodeFetch,
      },
    }),
}));

/* eslint-enable */
