import nock from "nock";

import { LatestVersionError } from "../src/exceptions/LatestVersionError";
import { wordpressVersions } from "../src/wordpress-versions";

import beta from "./version-check-responses/beta.json";

// TODO: Modify to use actual response like the beta test
test("wordpressVersions works correctly when only stable version is available", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [
        {
          response: "upgrade",
          current: "0.42.1",
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

// TODO: Modify to use actual response like the beta test
test("wordpressVersions works correctly when both stable and RC versions are available", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [
        {
          response: "development",
          current: "0.43-RC2",
        },
        {
          response: "upgrade",
          current: "0.42.1",
        },
      ],
      translations: [],
    });
  await expect(wordpressVersions()).resolves.toStrictEqual({
    beta: "0.43",
    rc: "0.43",
    stable: "0.42",
  });
});

test("wordpressVersions works correctly when both stable and beta versions are available", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, beta as Record<string, unknown>);
  await expect(wordpressVersions()).resolves.toStrictEqual({
    beta: "6.3",
    rc: null,
    stable: "6.2",
  });
});

test("wordpressVersions fails gracefully on connection issues", async () => {
  expect.assertions(1);
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("wordpressVersions fails gracefully on connection issues 2", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(404);
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("wordpressVersions fails gracefully on invalid response", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200);
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("wordpressVersions fails gracefully on invalid response 2", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      translations: [],
    });
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("wordpressVersions fails gracefully on invalid response 3", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [],
      translations: [],
    });
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("wordpressVersions fails gracefully on invalid response 4", async () => {
  expect.assertions(1);
  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, {
      offers: [
        {
          current: "0.42.1",
        },
      ],
      translations: [],
    });
  await expect(wordpressVersions()).rejects.toThrow(LatestVersionError);
});

test("wordpressVersions fails gracefully on invalid response 5", async () => {
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
