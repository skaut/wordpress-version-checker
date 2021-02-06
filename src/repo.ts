import * as github from '@actions/github';

export const repo = github.context.repo;
export const repoName = repo.owner + '/' + repo.repo;
