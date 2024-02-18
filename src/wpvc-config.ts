import { octokit } from "./octokit";

export async function WPVCConfig(): Promise<boolean> {
  const file = await octokit().rest.repos.getContent({
    owner: "",
    repo: "",
    path: "",
  });
  return file.data === null;
}
