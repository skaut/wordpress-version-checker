import nock from "nock";

import { latestWordPressVersion } from "../src/latest-version";

//nock.recorder.rec();

test("latestWordPressVersion works correctly", async () => {
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(200, {
    "0.40": "insecure",
    "0.41": "outdated",
    "0.42": "latest",
  });
  await expect(latestWordPressVersion()).resolves.toStrictEqual("0.42");
});
