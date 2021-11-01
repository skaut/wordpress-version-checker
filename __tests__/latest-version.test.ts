import { latestWordPressVersion } from "../src/latest-version";

test("latestWordPressVersion works correctly", () => {
	expect(latestWordPressVersion()).resolves.toStrictEqual("5.8")
});
