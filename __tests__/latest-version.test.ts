import { latestWordPressVersion } from "../src/latest-version";

test("latestWordPressVersion works correctly", async () => {
  await expect(latestWordPressVersion()).resolves.toStrictEqual("5.8");
});
