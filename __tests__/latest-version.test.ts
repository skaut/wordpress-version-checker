import nock from "nock";

import { latestWordPressVersion } from "../src/latest-version";

import { LatestVersionError } from "../src/exceptions/LatestVersionError";

beforeAll(() => {
  nock.disableNetConnect();
});
afterAll(() => {
  nock.enableNetConnect();
});

test("latestWordPressVersion works correctly", async () => {
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(200, {
    "0.40": "insecure",
    "0.41": "outdated",
    "0.42": "latest",
  });
  await expect(latestWordPressVersion()).resolves.toStrictEqual("0.42");
});

test("latestWordPressVersion fails gracefully on connection issues", async () => {
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on connection issues 2", async () => {
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(404);
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response", async () => {
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(200);
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response 2", async () => {
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(200, {
    "0.40": "insecure",
    "0.41": "outdated",
  });
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});
