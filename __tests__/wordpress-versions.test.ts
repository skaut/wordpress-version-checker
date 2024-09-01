import nock from "nock";

import { LatestVersionError } from "../src/exceptions/LatestVersionError";
import { wordpressVersions } from "../src/wordpress-versions";
import beta from "./version-check-responses/beta.json";
import rc from "./version-check-responses/rc.json";
import stable from "./version-check-responses/stable.json";

test("wordpressVersions works correctly when only stable version is available", async () => {
  expect.assertions(1);

  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, stable as Record<string, unknown>);

  await expect(wordpressVersions()).resolves.toStrictEqual({
    beta: null,
    rc: null,
    stable: "6.3",
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

test("wordpressVersions works correctly when stable, RC, and beta versions are available", async () => {
  expect.assertions(1);

  nock("https://api.wordpress.org")
    .get("/core/version-check/1.7/?channel=beta")
    .reply(200, rc as Record<string, unknown>);

  await expect(wordpressVersions()).resolves.toStrictEqual({
    beta: "6.3",
    rc: "6.3",
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
