import nock from "nock";

import { latestWordPressVersion } from "../src/latest-version";

import { LatestVersionError } from "../src/exceptions/LatestVersionError";

test("latestWordPressVersion works correctly", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(200, {
    "0.40": "insecure",
    "0.41": "outdated",
    "0.42": "latest",
  });
  await expect(latestWordPressVersion()).resolves.toBe("0.42");
});

test("latestWordPressVersion fails gracefully on connection issues", async () => {
  expect.assertions(1);
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on connection issues 2", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(404);
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(200);
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response 2", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(200, {
    "0.40": "insecure",
    "0.41": "outdated",
  });
  await expect(latestWordPressVersion()).rejects.toThrow(LatestVersionError);
});
