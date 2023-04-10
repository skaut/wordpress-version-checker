export interface Config {
  readme: string;
  channel?: "beta" | "rc" | "stable";
  assignees: Array<string>;
}
