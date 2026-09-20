export interface Config {
  assignees: Array<string>;
  channel: "beta" | "rc" | "stable";
  readme: Array<string>;
}
