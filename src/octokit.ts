import * as core from '@actions/core';
import * as github from '@actions/github';

export const octokit = github.getOctokit(core.getInput('repo-token'));
