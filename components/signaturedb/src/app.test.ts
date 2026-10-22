import assert from "node:assert/strict";
import test from "node:test";

import { buildServer } from "./app.ts";
import { createFeedService } from "./feedService.ts";
import type { StatePersistenceAdapter } from "./statePersistence.ts";

type CreateFeedServiceOptions = NonNullable<Parameters<typeof createFeedService>[0]>;
type PersistedFeedStateForTests = CreateFeedServiceOptions["persistenceAdapter"] extends
  | StatePersistenceAdapter<infer TState>
  | undefined
  ? TState
  : never;

function createMemoryAdapter<T>(state: T | null = null): StatePersistenceAdapter<T> {
  let currentState = state;

  return {
    async read() {
      return currentState;
    },
    async write(nextState: T) {
      currentState = nextState;
    }
  };
}

function createStubFetch() {
  return async (url: string) => {
    if (url.includes("mb-api.abuse.ch")) {
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            data: [
              {
                sha256_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                signature: "Test.Loader",
                first_seen: "2026-04-22T10:00:00Z",
                tags: ["loader", "trojan"]
              }
            ]
          });
        },
        async json() {
          return {
            data: [
              {
                sha256_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                signature: "Test.Loader",
                first_seen: "2026-04-22T10:00:00Z",
                tags: ["loader", "trojan"]
              }
            ]
          };
        }
      };
    }

    if (url.includes("urlhaus.abuse.ch/downloads/json_recent")) {
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify([
            {
              url: "https://bad.example/payload",
              url_status: "online",
              date_added: "2026-04-22T11:00:00Z",
              tags: ["malware"]
            }
          ]);
        },
        async json() {
          return [
            {
              url: "https://bad.example/payload",
              url_status: "online",
              date_added: "2026-04-22T11:00:00Z",
              tags: ["malware"]
            }
          ];
        }
      };
    }

    if (url.includes("yaraify-api.abuse.ch")) {
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            data: [
              {
                rule_uuid: "rule-001",
                rule_name: "Suspicious_Test_Rule",
                yara_rule: "rule Suspicious_Test_Rule { condition: true }",
                updated_at: "2026-04-22T12:00:00Z",
                tags: ["test"]
              }
            ]
          });
        },
        async json() {
          return {
            data: [
              {
                rule_uuid: "rule-001",
                rule_name: "Suspicious_Test_Rule",
                yara_rule: "rule Suspicious_Test_Rule { condition: true }",
                updated_at: "2026-04-22T12:00:00Z",
                tags: ["test"]
              }
            ]
          };
        }
      };
    }

    if (url.includes("suricata")) {
      return {
        ok: true,
        status: 200,
        async text() {
          return 'alert http any any -> any any (msg:"Test Suricata"; sid:1000001; rev:1;)';
        },
        async json() {
          return {};
        }
      };
    }

    if (url.includes("clamav")) {
      return {
        ok: true,
        status: 200,
        async text() {
          return "TestSig:0:*:41424344";
        },
        async json() {
          return {};
        }
      };
    }

    throw new Error(`Unexpected URL ${url}`);
  };
}

async function createTestApp() {
  process.env.FENRIR_ENDPOINT_TOKEN = "endpoint-secret";
  process.env.FENRIR_FEED_ADMIN_TOKEN = "admin-secret";

  const feedService = await createFeedService({
    persistenceAdapter: createMemoryAdapter<PersistedFeedStateForTests>(null),
    fetchImpl: createStubFetch() as any,
    config: {
      malwareBazaarAuthKey: "mb-key",
      yaraifyAuthKey: "yara-key"
    }
  });

  const app = buildServer({
    feedService
  });

  await app.ready();

  return {
    app,
    async cleanup() {
      await app.close();
      delete process.env.FENRIR_ENDPOINT_TOKEN;
      delete process.env.FENRIR_FEED_ADMIN_TOKEN;
    }
  };
}

test("admin sync populates a manifest and endpoint bundle", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const syncResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/admin/feeds/sync",
    headers: {
      authorization: "Bearer admin-secret"
    }
  });

  assert.equal(syncResponse.statusCode, 200);
  const syncPayload = syncResponse.json() as {
    version: string;
    counts: { hashes: number; urls: number; rules: number };
  };

  assert.equal(typeof syncPayload.version, "string");
  assert.equal(syncPayload.counts.hashes, 1);
  assert.equal(syncPayload.counts.urls, 1);
  assert.ok(syncPayload.counts.rules >= 3);

  const manifestResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/feeds/manifest"
  });

  assert.equal(manifestResponse.statusCode, 200);
  assert.equal(manifestResponse.json().counts.hashes, 1);

  const bundleResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/agent/bundle",
    headers: {
      authorization: "Bearer endpoint-secret"
    }
  });

  assert.equal(bundleResponse.statusCode, 200);
  const bundlePayload = bundleResponse.json() as {
    hashes: Array<{ value: string }>;
    urls: Array<{ url: string }>;
    rules: Array<{ ruleType: string }>;
    summary: { version: string };
  };

  assert.equal(bundlePayload.hashes.length, 1);
  assert.equal(bundlePayload.hashes[0].value, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(bundlePayload.urls[0].url, "https://bad.example/payload");
  assert.ok(bundlePayload.rules.some((rule) => rule.ruleType === "yara"));
  assert.equal(bundlePayload.summary.version, syncPayload.version);
});

test("etag support returns 304 when unchanged", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const syncResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/admin/feeds/sync",
    headers: {
      authorization: "Bearer admin-secret"
    }
  });

  const etag = syncResponse.headers.etag;
  assert.ok(etag);

  const manifestResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/feeds/manifest",
    headers: {
      "if-none-match": String(etag)
    }
  });

  assert.equal(manifestResponse.statusCode, 304);
});

test("endpoint bundle is protected by shared token when configured", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const response = await harness.app.inject({
    method: "GET",
    url: "/api/v1/agent/bundle"
  });

  assert.equal(response.statusCode, 401);
  assert.equal(response.json().error, "endpoint_auth_required");
});
