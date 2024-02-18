import * as github from "@actions/github";

export async function WPVCConfig(): Promise<boolean> {
  const octokit = github.getOctokit("");
  const file = await octokit.rest.repos.getContent({
    owner: "",
    repo: "",
    path: "",
  });
  return file.data === null;
}
