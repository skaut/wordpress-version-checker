import { mocked } from "jest-mock";

import type { Config } from "../src/interfaces/Config";
import { WPVCConfig } from "../src/wpvc-config";

test("", () => {
  const config: Config = {
    readme: [],
    channel: "stable",
    assignees: [],
  };

  mocked(WPVCConfig).mockResolvedValue(config);
});
