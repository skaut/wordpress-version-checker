import { mocked } from "jest-mock";

import { WPVCConfig } from "../src/wpvc-config";

test("", () => {
  mocked(WPVCConfig).mockResolvedValue(true);
});
