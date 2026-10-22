import Fastify from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";

import {
  type FeedService,
  type FeedSummary,
  createFeedServiceFromEnv
} from "./feedService.ts";

interface BuildServerOptions {
  feedService?: FeedService;
  logger?: boolean;
}

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

function parseAllowedOrigins() {
  const configured = process.env.FENRIR_ALLOWED_CORS_ORIGINS
    ?.split(",")
    .map((entry) => normalizeOrigin(entry))
    .filter((entry) => entry.length > 0);

  if (!configured || configured.length === 0) {
    return new Set(DEFAULT_ALLOWED_CORS_ORIGINS.map((entry) => normalizeOrigin(entry)));
  }

  return new Set(configured);
}

function readBearerToken(headers: Record<string, unknown>) {
  const authHeader = headers.authorization;
  if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length).trim();
    return token.length > 0 ? token : undefined;
  }

  const explicitHeader = headers["x-fenrir-token"];
  if (typeof explicitHeader === "string" && explicitHeader.trim().length > 0) {
    return explicitHeader.trim();
  }

  return undefined;
}

function requireSharedToken(
  request: { headers: Record<string, unknown> },
  reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } },
  expectedToken: string | undefined,
  errorCode: string
) {
  if (!expectedToken) {
    return true;
  }

  const presentedToken = readBearerToken(request.headers);
  if (!presentedToken || presentedToken !== expectedToken) {
    reply.code(401).send({
      error: errorCode
    });
    return false;
  }

  return true;
}

function setCachingHeaders(
  reply: {
    header: (name: string, value: string) => unknown;
    code: (statusCode: number) => { send: (payload?: unknown) => unknown };
  },
  summary: FeedSummary
) {
  reply.header("etag", summary.etag);
  reply.header("cache-control", "private, max-age=60");
  reply.header("last-modified", summary.generatedAt);
  reply.header("x-fenrir-version", summary.version);
}

function maybeReturnNotModified(
  request: { headers: Record<string, unknown> },
  reply: {
    header: (name: string, value: string) => unknown;
    code: (statusCode: number) => { send: (payload?: unknown) => unknown };
  },
  summary: FeedSummary
) {
  const ifNoneMatch = request.headers["if-none-match"];
  if (typeof ifNoneMatch === "string" && ifNoneMatch.trim() === summary.etag) {
    setCachingHeaders(reply, summary);
    reply.code(304).send();
    return true;
  }

  return false;
}

function asNdjson(items: unknown[]) {
  return items.map((item) => JSON.stringify(item)).join("\n") + (items.length > 0 ? "\n" : "");
}

export function buildServer(options: BuildServerOptions = {}) {
  const feedService = options.feedService ?? createFeedServiceFromEnv();
  const loggerEnabled = options.logger ?? true;
  const app = Fastify({
    logger: loggerEnabled
  });

  const allowedOrigins = parseAllowedOrigins();
  const allowAllOrigins = process.env.FENRIR_ALLOW_ALL_CORS_ORIGINS === "true";
  const endpointToken = process.env.FENRIR_ENDPOINT_TOKEN?.trim() || undefined;
  const adminToken = process.env.FENRIR_FEED_ADMIN_TOKEN?.trim() || undefined;

  void app.register(cors, {
    origin(origin, callback) {
      if (!origin || allowAllOrigins) {
        callback(null, true);
        return;
      }

      callback(null, allowedOrigins.has(normalizeOrigin(origin)));
    },
    methods: ["GET", "POST", "HEAD", "OPTIONS"]
  });

  app.get("/health", async () => {
    const summary = await feedService.getSummary();

    return {
      service: "fenrir-feed-service",
      status: "ok",
      version: summary.version,
      generatedAt: summary.generatedAt,
      sources: summary.sources,
      counts: summary.counts
    };
  });

  app.get("/api/v1/feeds/manifest", async (request, reply) => {
    const parsed = manifestQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "invalid_request",
        details: parsed.error.flatten()
      });
    }

    const summary = await feedService.getSummary();

    if (maybeReturnNotModified(request, reply, summary)) {
      return reply;
    }

    setCachingHeaders(reply, summary);

    return {
      version: summary.version,
      generatedAt: summary.generatedAt,
      lastSyncAt: summary.lastSyncAt,
      status: summary.status,
      sources: summary.sources,
      counts: parsed.data.includeCounts ? summary.counts : undefined
    };
  });

  app.get("/api/v1/agent/bundle", async (request, reply) => {
    if (!requireSharedToken(request, reply, endpointToken, "endpoint_auth_required")) {
      return reply;
    }

    const parsed = agentBundleQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "invalid_request",
        details: parsed.error.flatten()
      });
    }

    const bundle = await feedService.getBundle({
      hashesLimit: parsed.data.hashesLimit,
      urlsLimit: parsed.data.urlsLimit,
      rulesLimit: parsed.data.rulesLimit
    });

    if (maybeReturnNotModified(request, reply, bundle.summary)) {
      return reply;
    }

    setCachingHeaders(reply, bundle.summary);
    return bundle;
  });

  app.get("/api/v1/agent/hashes.ndjson", async (request, reply) => {
    if (!requireSharedToken(request, reply, endpointToken, "endpoint_auth_required")) {
      return reply;
    }

    const parsed = ndjsonQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "invalid_request",
        details: parsed.error.flatten()
      });
    }

    const bundle = await feedService.getBundle({
      hashesLimit: parsed.data.limit
    });

    if (maybeReturnNotModified(request, reply, bundle.summary)) {
      return reply;
    }

    setCachingHeaders(reply, bundle.summary);
    reply.header("content-type", "application/x-ndjson; charset=utf-8");

    const items = parsed.data.source
      ? bundle.hashes.filter((item) => item.source === parsed.data.source)
      : bundle.hashes;

    return reply.send(asNdjson(items));
  });

  app.get("/api/v1/agent/urls.ndjson", async (request, reply) => {
    if (!requireSharedToken(request, reply, endpointToken, "endpoint_auth_required")) {
      return reply;
    }

    const parsed = ndjsonQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "invalid_request",
        details: parsed.error.flatten()
      });
    }

    const bundle = await feedService.getBundle({
      urlsLimit: parsed.data.limit
    });

    if (maybeReturnNotModified(request, reply, bundle.summary)) {
      return reply;
    }

    setCachingHeaders(reply, bundle.summary);
    reply.header("content-type", "application/x-ndjson; charset=utf-8");

    const items = parsed.data.source
      ? bundle.urls.filter((item) => item.source === parsed.data.source)
      : bundle.urls;

    return reply.send(asNdjson(items));
  });

  app.get("/api/v1/agent/rules/yara", async (request, reply) => {
    if (!requireSharedToken(request, reply, endpointToken, "endpoint_auth_required")) {
      return reply;
    }

    const parsed = ndjsonQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "invalid_request",
        details: parsed.error.flatten()
      });
    }

    const bundle = await feedService.getBundle({
      rulesLimit: parsed.data.limit
    });

    if (maybeReturnNotModified(request, reply, bundle.summary)) {
      return reply;
    }

    setCachingHeaders(reply, bundle.summary);
    reply.header("content-type", "application/x-ndjson; charset=utf-8");

    const items = bundle.rules.filter(
      (item) => item.ruleType === "yara" && (!parsed.data.source || item.source === parsed.data.source)
    );

    return reply.send(asNdjson(items));
  });

  app.get("/api/v1/agent/rules/suricata", async (request, reply) => {
    if (!requireSharedToken(request, reply, endpointToken, "endpoint_auth_required")) {
      return reply;
    }

    const summary = await feedService.getSummary();
    const suricataText = await feedService.getRawRules("suricata");

    if (maybeReturnNotModified(request, reply, summary)) {
      return reply;
    }

    setCachingHeaders(reply, summary);
    reply.header("content-type", "text/plain; charset=utf-8");
    return reply.send(suricataText);
  });

  app.get("/api/v1/agent/rules/clamav", async (request, reply) => {
    if (!requireSharedToken(request, reply, endpointToken, "endpoint_auth_required")) {
      return reply;
    }

    const summary = await feedService.getSummary();
    const clamavText = await feedService.getRawRules("clamav");

    if (maybeReturnNotModified(request, reply, summary)) {
      return reply;
    }

    setCachingHeaders(reply, summary);
    reply.header("content-type", "text/plain; charset=utf-8");
    return reply.send(clamavText);
  });

  app.post("/api/v1/admin/feeds/sync", async (request, reply) => {
    if (!requireSharedToken(request, reply, adminToken, "admin_auth_required")) {
      return reply;
    }

    const result = await feedService.syncFromUpstream();

    setCachingHeaders(reply, result.summary);

    return reply.code(200).send({
      synced: true,
      version: result.summary.version,
      generatedAt: result.summary.generatedAt,
      status: result.summary.status,
      counts: result.summary.counts,
      sourceResults: result.sourceResults
    });
  });

  app.get("/api/v1/admin/feeds/summary", async (request, reply) => {
    if (!requireSharedToken(request, reply, adminToken, "admin_auth_required")) {
      return reply;
    }

    const summary = await feedService.getSummary();
    return summary;
  });

  app.setErrorHandler((error, _request, reply) => {
    app.log.error(error);

    if (!reply.sent) {
      const message = error instanceof Error ? error.message : "Unexpected error";

      reply.code(500).send({
        error: "internal_error",
        message
      });
    }
  });

  return app;
}
