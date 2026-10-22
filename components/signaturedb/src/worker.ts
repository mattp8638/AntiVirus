import { z } from "zod";

import { createFeedService, type FeedRule, type FeedService, type FeedSummary } from "./feedService.ts";
import { type D1Database } from "./statePersistence.ts";

interface WorkerEnv {
  fenrir?: D1Database;
  [key: string]: unknown;
}

interface Runtime {
  feedService: FeedService;
  endpointToken?: string;
  adminToken?: string;
  allowAllOrigins: boolean;
  allowedOrigins: Set<string>;
}

let runtimePromise: Promise<Runtime> | null = null;
let bootstrapSyncPromise: Promise<void> | null = null;
let bootstrapSyncCompleted = false;

const DEFAULT_ALLOWED_CORS_ORIGINS = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "https://api.fenrir-security.co.uk",
  "https://av.fenrir-security.co.uk"
];

const manifestQuerySchema = z.object({
  includeCounts: z.coerce.boolean().optional().default(true)
});

const agentBundleQuerySchema = z.object({
  hashesLimit: z.coerce.number().int().positive().max(50000).optional(),
  urlsLimit: z.coerce.number().int().positive().max(50000).optional(),
  rulesLimit: z.coerce.number().int().positive().max(5000).optional()
});

const ndjsonQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(50000).optional(),
  source: z.string().trim().min(1).optional()
});

function normalizeOrigin(value: string) {
  return value.trim().toLowerCase();
}

function parseAllowedOrigins(configuredOrigins: string | undefined) {
  const configured = configuredOrigins
    ?.split(",")
    .map((entry) => normalizeOrigin(entry))
    .filter((entry) => entry.length > 0);

  if (!configured || configured.length === 0) {
    return new Set(DEFAULT_ALLOWED_CORS_ORIGINS.map((entry) => normalizeOrigin(entry)));
  }

  return new Set(configured);
}

function readEnvString(env: WorkerEnv, key: string) {
  const value = env[key];
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parsePositiveInteger(value: string | undefined) {
  if (!value) {
    return undefined;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return undefined;
  }

  return Math.floor(parsed);
}

function parseBoolean(value: string | undefined) {
  return value?.trim().toLowerCase() === "true";
}

function queryToObject(url: URL) {
  return Object.fromEntries(url.searchParams.entries());
}

function applyCorsHeaders(request: Request, runtime: Runtime, headers: Headers) {
  const origin = request.headers.get("origin");
  if (!origin) {
    return;
  }

  const allowed = runtime.allowAllOrigins || runtime.allowedOrigins.has(normalizeOrigin(origin));
  if (!allowed) {
    return;
  }

  headers.set("access-control-allow-origin", runtime.allowAllOrigins ? "*" : origin);
  headers.set("access-control-allow-methods", "GET,POST,HEAD,OPTIONS");
  headers.set("access-control-allow-headers", "authorization,content-type,x-fenrir-token,if-none-match");
  headers.set("access-control-max-age", "86400");
  headers.set("vary", "origin");
}

function buildJsonResponse(
  request: Request,
  runtime: Runtime,
  payload: unknown,
  status = 200,
  initialHeaders?: HeadersInit
) {
  const headers = new Headers(initialHeaders);
  headers.set("content-type", "application/json; charset=utf-8");
  applyCorsHeaders(request, runtime, headers);

  return new Response(JSON.stringify(payload), {
    status,
    headers
  });
}

function buildTextResponse(
  request: Request,
  runtime: Runtime,
  body: string,
  status = 200,
  initialHeaders?: HeadersInit
) {
  const headers = new Headers(initialHeaders);
  applyCorsHeaders(request, runtime, headers);

  return new Response(body, {
    status,
    headers
  });
}

function buildEmptyResponse(request: Request, runtime: Runtime, status: number, initialHeaders?: HeadersInit) {
  const headers = new Headers(initialHeaders);
  applyCorsHeaders(request, runtime, headers);

  return new Response(null, {
    status,
    headers
  });
}

function readBearerToken(request: Request) {
  const authHeader = request.headers.get("authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length).trim();
    return token.length > 0 ? token : undefined;
  }

  const explicitHeader = request.headers.get("x-fenrir-token");
  if (explicitHeader && explicitHeader.trim().length > 0) {
    return explicitHeader.trim();
  }

  return undefined;
}

function requireSharedToken(
  request: Request,
  runtime: Runtime,
  expectedToken: string | undefined,
  errorCode: string
) {
  if (!expectedToken) {
    return null;
  }

  const presentedToken = readBearerToken(request);
  if (!presentedToken || presentedToken !== expectedToken) {
    return buildJsonResponse(request, runtime, { error: errorCode }, 401);
  }

  return null;
}

function setCachingHeaders(headers: Headers, summary: FeedSummary) {
  headers.set("etag", summary.etag);
  headers.set("cache-control", "private, max-age=60");
  headers.set("last-modified", summary.generatedAt);
  headers.set("x-fenrir-version", summary.version);
}

function isNotModified(request: Request, summary: FeedSummary) {
  const ifNoneMatch = request.headers.get("if-none-match");
  return typeof ifNoneMatch === "string" && ifNoneMatch.trim() === summary.etag;
}

function asNdjson(items: unknown[]) {
  return items.map((item) => JSON.stringify(item)).join("\n") + (items.length > 0 ? "\n" : "");
}

async function getRuntime(env: WorkerEnv): Promise<Runtime> {
  if (!runtimePromise) {
    runtimePromise = (async () => {
      const database = env.fenrir;
      if (!database) {
        throw new Error('Missing required D1 binding "fenrir" in Worker environment');
      }

      const feedService = await createFeedService({
        database,
        config: {
          malwareBazaarAuthKey: readEnvString(env, "FENRIR_MALWARE_BAZAAR_AUTH_KEY"),
          yaraifyAuthKey: readEnvString(env, "FENRIR_YARAIFY_AUTH_KEY"),
          urlhausAuthKey: readEnvString(env, "FENRIR_URLHAUS_AUTH_KEY"),
          extraSuricataUrl: readEnvString(env, "FENRIR_SURICATA_URL"),
          extraClamavUrl: readEnvString(env, "FENRIR_CLAMAV_URL"),
          maxHashes: parsePositiveInteger(readEnvString(env, "FENRIR_FEED_MAX_HASHES")),
          maxUrls: parsePositiveInteger(readEnvString(env, "FENRIR_FEED_MAX_URLS")),
          maxRules: parsePositiveInteger(readEnvString(env, "FENRIR_FEED_MAX_RULES"))
        }
      });

      return {
        feedService,
        endpointToken: readEnvString(env, "FENRIR_ENDPOINT_TOKEN"),
        adminToken: readEnvString(env, "FENRIR_FEED_ADMIN_TOKEN"),
        allowAllOrigins: parseBoolean(readEnvString(env, "FENRIR_ALLOW_ALL_CORS_ORIGINS")),
        allowedOrigins: parseAllowedOrigins(readEnvString(env, "FENRIR_ALLOWED_CORS_ORIGINS"))
      };
    })();
  }

  return runtimePromise;
}

function ensureBootstrapSync(runtime: Runtime) {
  if (bootstrapSyncCompleted) {
    return null;
  }

  if (bootstrapSyncPromise) {
    return bootstrapSyncPromise;
  }

  bootstrapSyncPromise = (async () => {
    const summary = await runtime.feedService.getSummary();
    if (summary.lastSyncAt) {
      bootstrapSyncCompleted = true;
      return;
    }

    console.log("No persisted D1 feed snapshot found; running bootstrap sync");
    await runtime.feedService.syncFromUpstream();
    bootstrapSyncCompleted = true;
    console.log("Bootstrap sync completed");
  })()
    .catch((error) => {
      console.error(error);
    })
    .finally(() => {
      bootstrapSyncPromise = null;
    });

  return bootstrapSyncPromise;
}

function filterRulesBySource(rules: FeedRule[], source: string | undefined, ruleType?: FeedRule["ruleType"]) {
  return rules.filter(
    (rule) => (!ruleType || rule.ruleType === ruleType) && (!source || rule.source === source)
  );
}

const worker = {
  async fetch(request: Request, env: WorkerEnv, ctx: ExecutionContext) {
    try {
      const runtime = await getRuntime(env);
      const bootstrapSync = ensureBootstrapSync(runtime);
      if (bootstrapSync) {
        ctx.waitUntil(bootstrapSync);
      }

      const url = new URL(request.url);
      const method = request.method.toUpperCase();
      const path = url.pathname;

      if (method === "OPTIONS") {
        return buildEmptyResponse(request, runtime, 204);
      }

      if (method === "GET" && path === "/health") {
        const summary = await runtime.feedService.getSummary();
        return buildJsonResponse(request, runtime, {
          service: "fenrir-feed-service",
          status: "ok",
          version: summary.version,
          generatedAt: summary.generatedAt,
          sources: summary.sources,
          counts: summary.counts
        });
      }

      if (method === "GET" && path === "/api/v1/feeds/manifest") {
        const parsed = manifestQuerySchema.safeParse(queryToObject(url));
        if (!parsed.success) {
          return buildJsonResponse(
            request,
            runtime,
            { error: "invalid_request", details: parsed.error.flatten() },
            400
          );
        }

        const summary = await runtime.feedService.getSummary();
        const headers = new Headers();
        setCachingHeaders(headers, summary);

        if (isNotModified(request, summary)) {
          return buildEmptyResponse(request, runtime, 304, headers);
        }

        return buildJsonResponse(
          request,
          runtime,
          {
            version: summary.version,
            generatedAt: summary.generatedAt,
            lastSyncAt: summary.lastSyncAt,
            status: summary.status,
            sources: summary.sources,
            counts: parsed.data.includeCounts ? summary.counts : undefined
          },
          200,
          headers
        );
      }

      if (method === "POST" && path === "/api/v1/admin/feeds/sync") {
        const authFailure = requireSharedToken(request, runtime, runtime.adminToken, "admin_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const result = await runtime.feedService.syncFromUpstream();
        const headers = new Headers();
        setCachingHeaders(headers, result.summary);

        return buildJsonResponse(
          request,
          runtime,
          {
            synced: true,
            version: result.summary.version,
            generatedAt: result.summary.generatedAt,
            status: result.summary.status,
            counts: result.summary.counts,
            sourceResults: result.sourceResults
          },
          200,
          headers
        );
      }

      if (method === "GET" && path === "/api/v1/admin/feeds/summary") {
        const authFailure = requireSharedToken(request, runtime, runtime.adminToken, "admin_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const summary = await runtime.feedService.getSummary();
        return buildJsonResponse(request, runtime, summary, 200);
      }

      if (method === "GET" && path === "/api/v1/agent/bundle") {
        const authFailure = requireSharedToken(request, runtime, runtime.endpointToken, "endpoint_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const parsed = agentBundleQuerySchema.safeParse(queryToObject(url));
        if (!parsed.success) {
          return buildJsonResponse(
            request,
            runtime,
            { error: "invalid_request", details: parsed.error.flatten() },
            400
          );
        }

        const bundle = await runtime.feedService.getBundle({
          hashesLimit: parsed.data.hashesLimit,
          urlsLimit: parsed.data.urlsLimit,
          rulesLimit: parsed.data.rulesLimit
        });
        const headers = new Headers();
        setCachingHeaders(headers, bundle.summary);

        if (isNotModified(request, bundle.summary)) {
          return buildEmptyResponse(request, runtime, 304, headers);
        }

        return buildJsonResponse(request, runtime, bundle, 200, headers);
      }

      if (method === "GET" && path === "/api/v1/agent/hashes.ndjson") {
        const authFailure = requireSharedToken(request, runtime, runtime.endpointToken, "endpoint_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const parsed = ndjsonQuerySchema.safeParse(queryToObject(url));
        if (!parsed.success) {
          return buildJsonResponse(
            request,
            runtime,
            { error: "invalid_request", details: parsed.error.flatten() },
            400
          );
        }

        const bundle = await runtime.feedService.getBundle({ hashesLimit: parsed.data.limit });
        const headers = new Headers();
        setCachingHeaders(headers, bundle.summary);
        headers.set("content-type", "application/x-ndjson; charset=utf-8");

        if (isNotModified(request, bundle.summary)) {
          return buildEmptyResponse(request, runtime, 304, headers);
        }

        const items = parsed.data.source
          ? bundle.hashes.filter((item) => item.source === parsed.data.source)
          : bundle.hashes;

        return buildTextResponse(request, runtime, asNdjson(items), 200, headers);
      }

      if (method === "GET" && path === "/api/v1/agent/urls.ndjson") {
        const authFailure = requireSharedToken(request, runtime, runtime.endpointToken, "endpoint_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const parsed = ndjsonQuerySchema.safeParse(queryToObject(url));
        if (!parsed.success) {
          return buildJsonResponse(
            request,
            runtime,
            { error: "invalid_request", details: parsed.error.flatten() },
            400
          );
        }

        const bundle = await runtime.feedService.getBundle({ urlsLimit: parsed.data.limit });
        const headers = new Headers();
        setCachingHeaders(headers, bundle.summary);
        headers.set("content-type", "application/x-ndjson; charset=utf-8");

        if (isNotModified(request, bundle.summary)) {
          return buildEmptyResponse(request, runtime, 304, headers);
        }

        const items = parsed.data.source
          ? bundle.urls.filter((item) => item.source === parsed.data.source)
          : bundle.urls;

        return buildTextResponse(request, runtime, asNdjson(items), 200, headers);
      }

      if (method === "GET" && path === "/api/v1/agent/rules/yara") {
        const authFailure = requireSharedToken(request, runtime, runtime.endpointToken, "endpoint_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const parsed = ndjsonQuerySchema.safeParse(queryToObject(url));
        if (!parsed.success) {
          return buildJsonResponse(
            request,
            runtime,
            { error: "invalid_request", details: parsed.error.flatten() },
            400
          );
        }

        const bundle = await runtime.feedService.getBundle({ rulesLimit: parsed.data.limit });
        const headers = new Headers();
        setCachingHeaders(headers, bundle.summary);
        headers.set("content-type", "application/x-ndjson; charset=utf-8");

        if (isNotModified(request, bundle.summary)) {
          return buildEmptyResponse(request, runtime, 304, headers);
        }

        return buildTextResponse(
          request,
          runtime,
          asNdjson(filterRulesBySource(bundle.rules, parsed.data.source, "yara")),
          200,
          headers
        );
      }

      if (method === "GET" && path === "/api/v1/agent/rules/suricata") {
        const authFailure = requireSharedToken(request, runtime, runtime.endpointToken, "endpoint_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const summary = await runtime.feedService.getSummary();
        const text = await runtime.feedService.getRawRules("suricata");
        const headers = new Headers({
          "content-type": "text/plain; charset=utf-8"
        });
        setCachingHeaders(headers, summary);

        if (isNotModified(request, summary)) {
          return buildEmptyResponse(request, runtime, 304, headers);
        }

        return buildTextResponse(request, runtime, text, 200, headers);
      }

      if (method === "GET" && path === "/api/v1/agent/rules/clamav") {
        const authFailure = requireSharedToken(request, runtime, runtime.endpointToken, "endpoint_auth_required");
        if (authFailure) {
          return authFailure;
        }

        const summary = await runtime.feedService.getSummary();
        const text = await runtime.feedService.getRawRules("clamav");
        const headers = new Headers({
          "content-type": "text/plain; charset=utf-8"
        });
        setCachingHeaders(headers, summary);

        if (isNotModified(request, summary)) {
          return buildEmptyResponse(request, runtime, 304, headers);
        }

        return buildTextResponse(request, runtime, text, 200, headers);
      }

      return buildJsonResponse(request, runtime, { error: "not_found" }, 404);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unexpected worker runtime error";
      const fallbackRuntime: Runtime = {
        feedService: await createFeedService({
          database: env.fenrir
        }),
        endpointToken: readEnvString(env, "FENRIR_ENDPOINT_TOKEN"),
        adminToken: readEnvString(env, "FENRIR_FEED_ADMIN_TOKEN"),
        allowAllOrigins: parseBoolean(readEnvString(env, "FENRIR_ALLOW_ALL_CORS_ORIGINS")),
        allowedOrigins: parseAllowedOrigins(readEnvString(env, "FENRIR_ALLOWED_CORS_ORIGINS"))
      };

      return buildJsonResponse(request, fallbackRuntime, { error: "worker_runtime_error", message }, 500);
    }
  },

  async scheduled(_controller: ScheduledController, env: WorkerEnv, ctx: ExecutionContext) {
    const runtime = await getRuntime(env);
    ctx.waitUntil(runtime.feedService.syncFromUpstream());
  }
};

export default worker;
