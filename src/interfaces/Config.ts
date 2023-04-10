export interface Config {
  readme: Array<string>;
  channel: "beta" | "rc" | "stable";
  assignees: Array<string>;
}
