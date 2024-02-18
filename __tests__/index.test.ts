import { mocked } from "jest-mock";

import { testFn } from "../src/index";

test("", () => {
  mocked(testFn).mockResolvedValue(true);
});
