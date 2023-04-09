import nock from "nock";

import { LatestVersionError } from "../src/exceptions/LatestVersionError";
import { wordpressVersions } from "../src/wordpress-versions";

test("latestWordPressVersion works correctly when only stable version", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [
        {
          response: "latest",
          current: "0.42",
        },
      ],
      translations: [],
    });
  await expect(wordpressVersions()).resolves.toStrictEqual({
    beta: null,
    rc: null,
    stable: "0.42",
  });
});

test("latestWordPressVersion fails gracefully on connection issues", async () => {
  expect.assertions(1);
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on connection issues 2", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org").get("/core/stable-check/1.0/").reply(404);
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200);
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response 2", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      translations: [],
    });
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response 3", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [],
      translations: [],
    });
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response 4", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [
        {
          current: "0.42",
        },
      ],
      translations: [],
    });
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("latestWordPressVersion fails gracefully on invalid response 5", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [
        {
          response: "latest",
        },
      ],
      translations: [],
    });
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});
