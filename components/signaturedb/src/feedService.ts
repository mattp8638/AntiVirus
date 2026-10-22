import { createHash } from "node:crypto";

import { createD1StatePersistenceAdapter, type D1Database, type StatePersistenceAdapter } from "./statePersistence.ts";

export type FeedRuleType = "yara" | "suricata" | "clamav";

export interface FeedHashIndicator {
  id: string;
  source: string;
  type: "sha256" | "sha1" | "md5";
  value: string;
  malwareFamily?: string;
  firstSeen?: string;
  reporter?: string;
  tags: string[];
}

export interface FeedUrlIndicator {
  id: string;
  source: string;
  url: string;
  host?: string;
  status?: string;
  threat?: string;
  firstSeen?: string;
  tags: string[];
}

export interface FeedRule {
  id: string;
  source: string;
  ruleType: FeedRuleType;
  name: string;
  content: string;
  sha256: string;
  updatedAt?: string;
  tags: string[];
}

export interface FeedSourceSummary {
  name: string;
  enabled: boolean;
  lastSuccessAt?: string;
  lastError?: string;
  fetchedItems: number;
}

export interface FeedSummary {
  version: string;
  etag: string;
  generatedAt: string;
  lastSyncAt?: string;
  status: "empty" | "ready" | "degraded";
  counts: {
    hashes: number;
    urls: number;
    rules: number;
    yaraRules: number;
    suricataLines: number;
    clamavLines: number;
  };
  sources: FeedSourceSummary[];
}

export interface FeedBundle {
  summary: FeedSummary;
  hashes: FeedHashIndicator[];
  urls: FeedUrlIndicator[];
  rules: FeedRule[];
}

interface PersistedFeedState {
  version: string;
  generatedAt: string;
  lastSyncAt?: string;
  status: "empty" | "ready" | "degraded";
  hashes: FeedHashIndicator[];
  urls: FeedUrlIndicator[];
  rules: FeedRule[];
  rawRules: Record<FeedRuleType, string>;
  sources: FeedSourceSummary[];
}

interface FeedSourceConfig {
  malwareBazaarAuthKey?: string;
  yaraifyAuthKey?: string;
  urlhausAuthKey?: string;
  extraSuricataUrl?: string;
  extraClamavUrl?: string;
}

interface FeedServiceConfig extends FeedSourceConfig {
  maxHashes: number;
  maxUrls: number;
  maxRules: number;
}

interface SyncSourceResult {
  source: string;
  ok: boolean;
  fetchedItems: number;
  error?: string;
}

export interface FeedSyncResult {
  summary: FeedSummary;
  sourceResults: SyncSourceResult[];
}

export interface FeedService {
  getSummary(): Promise<FeedSummary>;
  getBundle(options?: { hashesLimit?: number; urlsLimit?: number; rulesLimit?: number }): Promise<FeedBundle>;
  syncFromUpstream(): Promise<FeedSyncResult>;
  getRawRules(ruleType: FeedRuleType): Promise<string>;
}

interface HttpLikeResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json(): Promise<any>;
}

type FetchImpl = (input: string, init?: RequestInit) => Promise<HttpLikeResponse>;

const DEFAULT_STATE_PATH = ".fenrir-feed-state.json";
const DEFAULT_MAX_HASHES = 20_000;
const DEFAULT_MAX_URLS = 10_000;
const DEFAULT_MAX_RULES = 2_000;
const EMPTY_RAW_RULES: Record<FeedRuleType, string> = {
  yara: "",
  suricata: "",
  clamav: ""
};

const MALWARE_BAZAAR_ENDPOINT = "https://mb-api.abuse.ch/api/v1/";
const YARAIFY_ENDPOINT = "https://yaraify-api.abuse.ch/api/v1/";
const URLHAUS_URLS_RECENT_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/urls/recent/";
const URLHAUS_PAYLOADS_RECENT_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/payloads/recent/";
const URLHAUS_SURICATA = "https://urlhaus.abuse.ch/downloads/ids/";

function sha256(input: string) {
  return createHash("sha256").update(input).digest("hex");
}

function normaliseList(values: string[] | undefined) {
  return Array.from(new Set((values ?? []).map((value) => value.trim()).filter((value) => value.length > 0)));
}

function toIsoDate(value: unknown) {
  if (typeof value !== "string" || value.trim().length === 0) {
    return undefined;
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return undefined;
  }

  return parsed.toISOString();
}

function parseIntegerEnv(name: string, fallback: number) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
}

function readOptionalEnv(name: string) {
  const value = process.env[name];
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function createEmptyState(): PersistedFeedState {
  return {
    version: "bootstrap",
    generatedAt: new Date(0).toISOString(),
    lastSyncAt: undefined,
    status: "empty",
    hashes: [],
    urls: [],
    rules: [],
    rawRules: { ...EMPTY_RAW_RULES },
    sources: []
  };
}

function toSummary(state: PersistedFeedState): FeedSummary {
  const yaraRules = state.rules.filter((rule) => rule.ruleType === "yara").length;
  const suricataLines = state.rawRules.suricata
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#")).length;
  const clamavLines = state.rawRules.clamav
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#")).length;

  return {
    version: state.version,
    etag: `W/"${state.version}"`,
    generatedAt: state.generatedAt,
    lastSyncAt: state.lastSyncAt,
    status: state.status,
    counts: {
      hashes: state.hashes.length,
      urls: state.urls.length,
      rules: state.rules.length,
      yaraRules,
      suricataLines,
      clamavLines
    },
    sources: state.sources
  };
}

function limitNewestBy<T>(items: T[], maxItems: number, getDate: (item: T) => string | undefined) {
  return [...items]
    .sort((left, right) => {
      const leftDate = getDate(left) ?? "";
      const rightDate = getDate(right) ?? "";
      return rightDate.localeCompare(leftDate);
    })
    .slice(0, maxItems);
}

async function safeReadState(adapter: StatePersistenceAdapter<PersistedFeedState>) {
  const state = await adapter.read();
  return state ?? createEmptyState();
}

async function createJsonFilePersistenceAdapter(
  stateFilePath: string
): Promise<StatePersistenceAdapter<PersistedFeedState>> {
  const path = stateFilePath;
  const [fs, pathModule] = await Promise.all([import("node:fs/promises"), import("node:path")]);
  const { mkdir, readFile, writeFile } = fs;
  const { dirname } = pathModule;

  return {
    async read() {
      try {
        const raw = await readFile(path, "utf8");
        const trimmed = raw.trim();
        if (trimmed.length === 0) {
          return null;
        }

        return JSON.parse(trimmed) as PersistedFeedState;
      } catch (error: any) {
        if (error && error.code === "ENOENT") {
          return null;
        }

        throw error;
      }
    },
    async write(state) {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, `${JSON.stringify(state, null, 2)}\n`, "utf8");
    }
  };
}

async function fetchText(fetchImpl: FetchImpl, url: string, init?: RequestInit) {
  const response = await fetchImpl(url, init);
  if (!response.ok) {
    throw new Error(`Upstream returned HTTP ${response.status} for ${url}`);
  }
  return response.text();
}

async function fetchJson(fetchImpl: FetchImpl, url: string, init?: RequestInit) {
  const response = await fetchImpl(url, init);
  if (!response.ok) {
    throw new Error(`Upstream returned HTTP ${response.status} for ${url}`);
  }
  return response.json();
}

function buildVersion(state: Omit<PersistedFeedState, "version">) {
  const material = JSON.stringify({
    generatedAt: state.generatedAt,
    hashes: state.hashes.map((item) => item.id),
    urls: state.urls.map((item) => item.id),
    rules: state.rules.map((item) => item.sha256),
    rawRules: {
      suricata: sha256(state.rawRules.suricata),
      clamav: sha256(state.rawRules.clamav)
    },
    sources: state.sources.map((source) => ({
      name: source.name,
      enabled: source.enabled,
      lastSuccessAt: source.lastSuccessAt,
      lastError: source.lastError,
      fetchedItems: source.fetchedItems
    }))
  });

  return sha256(material).slice(0, 24);
}

function mergeById<T extends { id: string }>(existing: T[], incoming: T[]) {
  const merged = new Map<string, T>();
  for (const item of existing) {
    merged.set(item.id, item);
  }
  for (const item of incoming) {
    merged.set(item.id, item);
  }
  return Array.from(merged.values());
}

function parseHostFromUrl(urlValue: string) {
  try {
    return new URL(urlValue).hostname;
  } catch {
    return undefined;
  }
}

function mapMalwareBazaarSamples(payload: any): FeedHashIndicator[] {
  const data = Array.isArray(payload?.data) ? payload.data : [];
  const items: FeedHashIndicator[] = [];

  for (const entry of data) {
    const sha256Value = typeof entry?.sha256_hash === "string" ? entry.sha256_hash.trim().toLowerCase() : undefined;
    if (!sha256Value) {
      continue;
    }

    const tags = normaliseList(
      Array.isArray(entry?.tags)
        ? entry.tags.map((tag: unknown) => String(tag))
        : typeof entry?.signature === "string"
          ? [entry.signature]
          : []
    );

    items.push({
      id: `malwarebazaar:sha256:${sha256Value}`,
      source: "malwarebazaar",
      type: "sha256",
      value: sha256Value,
      malwareFamily: typeof entry?.signature === "string" ? entry.signature : undefined,
      firstSeen: toIsoDate(entry?.first_seen),
      reporter: typeof entry?.reporter === "string" ? entry.reporter : undefined,
      tags
    });
  }

  return items;
}

function mapUrlhausRecent(payload: any): FeedUrlIndicator[] {
  const sourceItems = Array.isArray(payload)
    ? payload
    : Array.isArray(payload?.urls)
      ? payload.urls
      : Array.isArray(payload?.data)
        ? payload.data
        : [];

  const items: FeedUrlIndicator[] = [];

  for (const entry of sourceItems) {
    const urlValue = typeof entry?.url === "string" ? entry.url : undefined;
    if (!urlValue) {
      continue;
    }

    const tags = normaliseList(
      Array.isArray(entry?.tags) ? entry.tags.map((tag: unknown) => String(tag)) : []
    );

    items.push({
      id: `urlhaus:url:${sha256(urlValue)}`,
      source: "urlhaus",
      url: urlValue,
      host: parseHostFromUrl(urlValue),
      status: typeof entry?.url_status === "string" ? entry.url_status : undefined,
      threat:
        typeof entry?.threat === "string"
          ? entry.threat
          : typeof entry?.signature === "string"
            ? entry.signature
            : undefined,
      firstSeen: toIsoDate(entry?.date_added ?? entry?.firstseen),
      tags
    });
  }

  return items;
}

function mapUrlhausRecentPayloads(payload: any): FeedHashIndicator[] {
  const sourceItems = Array.isArray(payload?.payloads)
    ? payload.payloads
    : Array.isArray(payload?.data)
      ? payload.data
      : [];

  const items: FeedHashIndicator[] = [];

  for (const entry of sourceItems) {
    const sha256Value =
      typeof entry?.sha256_hash === "string" ? entry.sha256_hash.trim().toLowerCase() : undefined;
    const md5Value = typeof entry?.md5_hash === "string" ? entry.md5_hash.trim().toLowerCase() : undefined;
    if (!sha256Value && !md5Value) {
      continue;
    }

    const type: FeedHashIndicator["type"] = sha256Value ? "sha256" : "md5";
    const value = sha256Value ?? md5Value!;

    const tags = normaliseList([
      typeof entry?.file_type === "string" ? entry.file_type : "",
      typeof entry?.magika === "string" ? entry.magika : "",
      typeof entry?.signature === "string" ? entry.signature : ""
    ]);

    items.push({
      id: `urlhaus:${type}:${value}`,
      source: "urlhaus",
      type,
      value,
      malwareFamily: typeof entry?.signature === "string" ? entry.signature : undefined,
      firstSeen: toIsoDate(entry?.firstseen),
      tags
    });
  }

  return items;
}

function mapYaraifyRules(payload: any): FeedRule[] {
  const data = Array.isArray(payload?.data) ? payload.data : [];
  const items: FeedRule[] = [];

  for (const entry of data) {
    const uuid = typeof entry?.rule_uuid === "string" ? entry.rule_uuid : typeof entry?.uuid === "string" ? entry.uuid : undefined;
    const content = typeof entry?.yara_rule === "string" ? entry.yara_rule : typeof entry?.rule === "string" ? entry.rule : undefined;

    if (!uuid || !content) {
      continue;
    }

    items.push({
      id: `yaraify:${uuid}`,
      source: "yaraify",
      ruleType: "yara",
      name: typeof entry?.rule_name === "string" ? entry.rule_name : typeof entry?.name === "string" ? entry.name : uuid,
      content,
      sha256: sha256(content),
      updatedAt: toIsoDate(entry?.updated_at ?? entry?.date),
      tags: normaliseList(Array.isArray(entry?.tags) ? entry.tags.map((tag: unknown) => String(tag)) : [])
    });
  }

  return items;
}

function mapRawLinesToRules(source: string, ruleType: FeedRuleType, rawText: string): FeedRule[] {
  const lines = rawText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  return lines.map((line, index) => ({
    id: `${source}:${ruleType}:${index}:${sha256(line).slice(0, 12)}`,
    source,
    ruleType,
    name: `${source}-${ruleType}-${index + 1}`,
    content: line,
    sha256: sha256(line),
    updatedAt: new Date().toISOString(),
    tags: []
  }));
}

class FeedServiceImpl implements FeedService {
  constructor(
    private readonly adapter: StatePersistenceAdapter<PersistedFeedState>,
    private readonly config: FeedServiceConfig,
    private readonly fetchImpl: FetchImpl
  ) {}

  async getSummary() {
    const state = await safeReadState(this.adapter);
    return toSummary(state);
  }

  async getBundle(options?: { hashesLimit?: number; urlsLimit?: number; rulesLimit?: number }) {
    const state = await safeReadState(this.adapter);
    const summary = toSummary(state);

    return {
      summary,
      hashes: state.hashes.slice(0, options?.hashesLimit ?? state.hashes.length),
      urls: state.urls.slice(0, options?.urlsLimit ?? state.urls.length),
      rules: state.rules.slice(0, options?.rulesLimit ?? state.rules.length)
    };
  }

  async getRawRules(ruleType: FeedRuleType) {
    const state = await safeReadState(this.adapter);
    return state.rawRules[ruleType];
  }

  async syncFromUpstream(): Promise<FeedSyncResult> {
    const now = new Date().toISOString();
    const currentState = await safeReadState(this.adapter);

    const incomingHashes: FeedHashIndicator[] = [];
    const incomingUrls: FeedUrlIndicator[] = [];
    const incomingRules: FeedRule[] = [];
    const rawRules: Record<FeedRuleType, string> = {
      ...currentState.rawRules
    };

    const sourceResults: SyncSourceResult[] = [];

    if (this.config.malwareBazaarAuthKey) {
      try {
        const payload = await fetchJson(this.fetchImpl, MALWARE_BAZAAR_ENDPOINT, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Auth-Key": this.config.malwareBazaarAuthKey
          },
          body: new URLSearchParams({
            query: "get_recent",
            selector: "time"
          }).toString()
        });

        const mapped = mapMalwareBazaarSamples(payload);
        incomingHashes.push(...mapped);
        sourceResults.push({
          source: "malwarebazaar",
          ok: true,
          fetchedItems: mapped.length
        });
      } catch (error: any) {
        sourceResults.push({
          source: "malwarebazaar",
          ok: false,
          fetchedItems: 0,
          error: error.message
        });
      }
    } else {
      sourceResults.push({
        source: "malwarebazaar",
        ok: false,
        fetchedItems: 0,
        error: "Disabled: missing MALWARE_BAZAAR auth key"
      });
    }

    if (this.config.urlhausAuthKey) {
      const init: RequestInit = {
        headers: {
          "Auth-Key": this.config.urlhausAuthKey
        }
      };

      try {
        const payload = await fetchJson(this.fetchImpl, URLHAUS_URLS_RECENT_ENDPOINT, init);
        const mapped = mapUrlhausRecent(payload);
        incomingUrls.push(...mapped);
        sourceResults.push({
          source: "urlhaus",
          ok: true,
          fetchedItems: mapped.length
        });
      } catch (error: any) {
        sourceResults.push({
          source: "urlhaus",
          ok: false,
          fetchedItems: 0,
          error: error.message
        });
      }

      try {
        const payload = await fetchJson(this.fetchImpl, URLHAUS_PAYLOADS_RECENT_ENDPOINT, init);
        const mapped = mapUrlhausRecentPayloads(payload);
        incomingHashes.push(...mapped);
        sourceResults.push({
          source: "urlhaus-payloads",
          ok: true,
          fetchedItems: mapped.length
        });
      } catch (error: any) {
        sourceResults.push({
          source: "urlhaus-payloads",
          ok: false,
          fetchedItems: 0,
          error: error.message
        });
      }
    } else {
      sourceResults.push({
        source: "urlhaus",
        ok: false,
        fetchedItems: 0,
        error: "Disabled: missing URLhaus auth key"
      });
      sourceResults.push({
        source: "urlhaus-payloads",
        ok: false,
        fetchedItems: 0,
        error: "Disabled: missing URLhaus auth key"
      });
    }

    if (this.config.yaraifyAuthKey) {
      try {
        const payload = await fetchJson(this.fetchImpl, YARAIFY_ENDPOINT, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Auth-Key": this.config.yaraifyAuthKey
          },
          body: new URLSearchParams({
            query: "recent_yararules"
          }).toString()
        });

        const mapped = mapYaraifyRules(payload);
        incomingRules.push(...mapped);
        rawRules.yara = mapped.map((item) => item.content).join("\n\n");
        sourceResults.push({
          source: "yaraify",
          ok: true,
          fetchedItems: mapped.length
        });
      } catch (error: any) {
        sourceResults.push({
          source: "yaraify",
          ok: false,
          fetchedItems: 0,
          error: error.message
        });
      }
    } else {
      sourceResults.push({
        source: "yaraify",
        ok: false,
        fetchedItems: 0,
        error: "Disabled: missing YARAify auth key"
      });
    }

    try {
      const init: RequestInit | undefined = this.config.urlhausAuthKey
        ? {
            headers: {
              "Auth-Key": this.config.urlhausAuthKey
            }
          }
        : undefined;
      const suricataText = await fetchText(
        this.fetchImpl,
        this.config.extraSuricataUrl ?? URLHAUS_SURICATA,
        init
      );
      rawRules.suricata = suricataText;
      incomingRules.push(...mapRawLinesToRules("urlhaus", "suricata", suricataText));
      sourceResults.push({
        source: "suricata",
        ok: true,
        fetchedItems: rawRules.suricata.split(/\r?\n/).filter((line) => line.trim().length > 0).length
      });
    } catch (error: any) {
      sourceResults.push({
        source: "suricata",
        ok: false,
        fetchedItems: 0,
        error: error.message
      });
    }

    if (this.config.extraClamavUrl) {
      try {
        const init: RequestInit | undefined = this.config.urlhausAuthKey
          ? {
              headers: {
                "Auth-Key": this.config.urlhausAuthKey
              }
            }
          : undefined;

        const clamavText = await fetchText(this.fetchImpl, this.config.extraClamavUrl, init);
        rawRules.clamav = clamavText;
        incomingRules.push(...mapRawLinesToRules("urlhaus", "clamav", clamavText));
        sourceResults.push({
          source: "clamav",
          ok: true,
          fetchedItems: rawRules.clamav.split(/\r?\n/).filter((line) => line.trim().length > 0).length
        });
      } catch (error: any) {
        sourceResults.push({
          source: "clamav",
          ok: false,
          fetchedItems: 0,
          error: error.message
        });
      }
    } else {
      sourceResults.push({
        source: "clamav",
        ok: false,
        fetchedItems: 0,
        error: "Disabled: missing ClamAV feed URL"
      });
    }

    const mergedHashes = limitNewestBy(mergeById(currentState.hashes, incomingHashes), this.config.maxHashes, (item) => item.firstSeen);
    const mergedUrls = limitNewestBy(mergeById(currentState.urls, incomingUrls), this.config.maxUrls, (item) => item.firstSeen);
    const mergedRules = limitNewestBy(mergeById(currentState.rules, incomingRules), this.config.maxRules, (item) => item.updatedAt);

    const sources: FeedSourceSummary[] = sourceResults.map((result) => ({
      name: result.source,
      enabled: !result.error?.startsWith("Disabled"),
      lastSuccessAt: result.ok ? now : currentState.sources.find((item) => item.name === result.source)?.lastSuccessAt,
      lastError: result.ok ? undefined : result.error,
      fetchedItems: result.fetchedItems
    }));

    const status: PersistedFeedState["status"] = sourceResults.some((result) => result.ok)
      ? sourceResults.some((result) => !result.ok)
        ? "degraded"
        : "ready"
      : currentState.hashes.length > 0 || currentState.urls.length > 0 || currentState.rules.length > 0
        ? "degraded"
        : "empty";

    const nextStateWithoutVersion: Omit<PersistedFeedState, "version"> = {
      generatedAt: now,
      lastSyncAt: now,
      status,
      hashes: mergedHashes,
      urls: mergedUrls,
      rules: mergedRules,
      rawRules,
      sources
    };

    const nextState: PersistedFeedState = {
      ...nextStateWithoutVersion,
      version: buildVersion(nextStateWithoutVersion)
    };

    await this.adapter.write(nextState);

    return {
      summary: toSummary(nextState),
      sourceResults
    };
  }
}

export async function createFeedService(options?: {
  persistenceAdapter?: StatePersistenceAdapter<PersistedFeedState>;
  database?: D1Database;
  stateFilePath?: string;
  fetchImpl?: FetchImpl;
  config?: Partial<FeedServiceConfig>;
}): Promise<FeedService> {
  const adapter =
    options?.persistenceAdapter ??
    (options?.database
      ? createD1StatePersistenceAdapter<PersistedFeedState>(options.database, "feed_service")
      : await createJsonFilePersistenceAdapter(options?.stateFilePath ?? DEFAULT_STATE_PATH));

  const config: FeedServiceConfig = {
    malwareBazaarAuthKey: options?.config?.malwareBazaarAuthKey ?? readOptionalEnv("FENRIR_MALWARE_BAZAAR_AUTH_KEY"),
    yaraifyAuthKey: options?.config?.yaraifyAuthKey ?? readOptionalEnv("FENRIR_YARAIFY_AUTH_KEY"),
    urlhausAuthKey: options?.config?.urlhausAuthKey ?? readOptionalEnv("FENRIR_URLHAUS_AUTH_KEY"),
    extraSuricataUrl: options?.config?.extraSuricataUrl ?? readOptionalEnv("FENRIR_SURICATA_URL"),
    extraClamavUrl: options?.config?.extraClamavUrl ?? readOptionalEnv("FENRIR_CLAMAV_URL"),
    maxHashes: options?.config?.maxHashes ?? parseIntegerEnv("FENRIR_FEED_MAX_HASHES", DEFAULT_MAX_HASHES),
    maxUrls: options?.config?.maxUrls ?? parseIntegerEnv("FENRIR_FEED_MAX_URLS", DEFAULT_MAX_URLS),
    maxRules: options?.config?.maxRules ?? parseIntegerEnv("FENRIR_FEED_MAX_RULES", DEFAULT_MAX_RULES)
  };

  return new FeedServiceImpl(adapter, config, options?.fetchImpl ?? (fetch as FetchImpl));
}

export function createFeedServiceFromEnv() {
  const servicePromise = createFeedService({
    stateFilePath: readOptionalEnv("FENRIR_FEED_STATE_FILE_PATH") ?? DEFAULT_STATE_PATH
  });

  return {
    async getSummary() {
      const service = await servicePromise;
      return service.getSummary();
    },
    async getBundle(options?: { hashesLimit?: number; urlsLimit?: number; rulesLimit?: number }) {
      const service = await servicePromise;
      return service.getBundle(options);
    },
    async syncFromUpstream() {
      const service = await servicePromise;
      return service.syncFromUpstream();
    },
    async getRawRules(ruleType: FeedRuleType) {
      const service = await servicePromise;
      return service.getRawRules(ruleType);
    }
  } satisfies FeedService;
}
