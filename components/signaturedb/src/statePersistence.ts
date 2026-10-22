export interface StatePersistenceAdapter<TState> {
  read(): Promise<TState | null>;
  write(state: TState): Promise<void>;
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[] } | T[] | null>;
  run<T = unknown>(): Promise<T>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch?(statements: D1PreparedStatement[]): Promise<unknown>;
}

const STATE_TABLE_NAME = "fenrir_state_store";
const HASH_TABLE_NAME = "fenrir_hash_indicators";
const URL_TABLE_NAME = "fenrir_url_indicators";
const RULE_TABLE_NAME = "fenrir_rule_indicators";
const SOURCE_TABLE_NAME = "fenrir_source_status";
const RAW_RULE_TABLE_NAME = "fenrir_raw_rule_text";
const initializedDatabases = new WeakMap<D1Database, Promise<void>>();
const MAX_RAW_RULE_CONTENT_LENGTH = 500_000;

interface JsonRowWithId {
  id: string;
  payload: unknown;
}

interface JsonRowWithName {
  name: string;
  payload: unknown;
}

interface RawRuleRow {
  ruleType: string;
  content: string;
}

type FeedStatus = "empty" | "ready" | "degraded";

interface CompactFeedSnapshot {
  version: string;
  generatedAt: string;
  lastSyncAt?: string;
  status: FeedStatus;
}

const D1_BATCH_SIZE = 200;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asJsonRowsWithId(value: unknown): JsonRowWithId[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const rows: JsonRowWithId[] = [];

  for (const entry of value) {
    if (!isObject(entry)) {
      continue;
    }

    const idValue = entry.id;
    if (typeof idValue !== "string" || idValue.trim().length === 0) {
      continue;
    }

    rows.push({
      id: idValue,
      payload: entry
    });
  }

  return rows;
}

function asJsonRowsWithName(value: unknown): JsonRowWithName[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const rows: JsonRowWithName[] = [];

  for (const entry of value) {
    if (!isObject(entry)) {
      continue;
    }

    const nameValue = entry.name;
    if (typeof nameValue !== "string" || nameValue.trim().length === 0) {
      continue;
    }

    rows.push({
      name: nameValue,
      payload: entry
    });
  }

  return rows;
}

function asRawRuleRows(value: unknown): RawRuleRow[] {
  if (!isObject(value)) {
    return [];
  }

  const rows: RawRuleRow[] = [];

  for (const [ruleType, content] of Object.entries(value)) {
    if (typeof content !== "string") {
      continue;
    }

    if (content.length > MAX_RAW_RULE_CONTENT_LENGTH) {
      continue;
    }

    rows.push({
      ruleType,
      content
    });
  }

  return rows;
}

function fromAllResult<T>(result: unknown): T[] {
  if (Array.isArray(result)) {
    return result as T[];
  }

  if (isObject(result) && Array.isArray(result.results)) {
    return result.results as T[];
  }

  return [];
}

function parseJsonOrNull(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function readFeedStatus(value: unknown): FeedStatus {
  return value === "ready" || value === "degraded" || value === "empty" ? value : "empty";
}

function createCompactFeedSnapshot(state: unknown): CompactFeedSnapshot {
  const source = isObject(state) ? state : {};

  return {
    version: typeof source.version === "string" ? source.version : "bootstrap",
    generatedAt:
      typeof source.generatedAt === "string" ? source.generatedAt : new Date(0).toISOString(),
    lastSyncAt: typeof source.lastSyncAt === "string" ? source.lastSyncAt : undefined,
    status: readFeedStatus(source.status)
  };
}

async function loadJsonPayloadRows(database: D1Database, tableName: string) {
  const queryResult = await database
    .prepare(`SELECT payload_json FROM ${tableName}`)
    .all<{ payload_json?: string }>();

  const rows = fromAllResult<{ payload_json?: string }>(queryResult);
  const parsed: unknown[] = [];

  for (const row of rows) {
    if (typeof row?.payload_json !== "string") {
      continue;
    }

    const value = parseJsonOrNull(row.payload_json);
    if (value !== null) {
      parsed.push(value);
    }
  }

  return parsed;
}

async function loadRawRuleMap(database: D1Database) {
  const queryResult = await database
    .prepare(`SELECT rule_type, content FROM ${RAW_RULE_TABLE_NAME}`)
    .all<{ rule_type?: string; content?: string }>();

  const rows = fromAllResult<{ rule_type?: string; content?: string }>(queryResult);
  const map: Record<string, string> = {};

  for (const row of rows) {
    if (typeof row?.rule_type !== "string" || typeof row?.content !== "string") {
      continue;
    }

    map[row.rule_type] = row.content;
  }

  return map;
}

function hydrateExpandedFeedState(
  snapshot: unknown,
  hashes: unknown[],
  urls: unknown[],
  rules: unknown[],
  sources: unknown[],
  rawRules: Record<string, string>
) {
  const derivedRawRules = deriveRawRuleMapFromRules(rules);
  const state: Record<string, unknown> = isObject(snapshot) ? { ...snapshot } : {};

  state.hashes = hashes;
  state.urls = urls;
  state.rules = rules;
  state.sources = sources;
  const rawRuleDefaults = {
    yara: "",
    suricata: "",
    clamav: ""
  };

  state.rawRules = {
    ...rawRuleDefaults,
    ...derivedRawRules,
    ...rawRules
  };

  if (typeof state.version !== "string") {
    state.version = "bootstrap";
  }

  if (typeof state.generatedAt !== "string") {
    state.generatedAt = new Date(0).toISOString();
  }

  state.status = readFeedStatus(state.status);

  return state;
}

function deriveRawRuleMapFromRules(rules: unknown[]) {
  const grouped: Record<string, string[]> = {
    yara: [],
    suricata: [],
    clamav: []
  };

  for (const entry of rules) {
    if (!isObject(entry)) {
      continue;
    }

    const ruleType = entry.ruleType;
    const content = entry.content;

    if (typeof ruleType !== "string" || typeof content !== "string") {
      continue;
    }

    if (!Object.hasOwn(grouped, ruleType)) {
      continue;
    }

    grouped[ruleType].push(content);
  }

  return {
    yara: grouped.yara.join("\n\n"),
    suricata: grouped.suricata.join("\n"),
    clamav: grouped.clamav.join("\n")
  };
}

async function replaceJsonRowsById(
  database: D1Database,
  tableName: string,
  rows: JsonRowWithId[],
  updatedAt: string
) {
  await database.prepare(`DELETE FROM ${tableName}`).run();

  const statements: D1PreparedStatement[] = [];

  for (const row of rows) {
    statements.push(
      database
        .prepare(
          `INSERT INTO ${tableName} (id, payload_json, updated_at)
           VALUES (?1, ?2, ?3)
           ON CONFLICT(id)
           DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at`
        )
        .bind(row.id, JSON.stringify(row.payload), updatedAt)
    );
  }

  await runStatements(database, statements);
}

async function replaceJsonRowsByName(
  database: D1Database,
  tableName: string,
  rows: JsonRowWithName[],
  updatedAt: string
) {
  await database.prepare(`DELETE FROM ${tableName}`).run();

  const statements: D1PreparedStatement[] = [];

  for (const row of rows) {
    statements.push(
      database
        .prepare(
          `INSERT INTO ${tableName} (source_name, payload_json, updated_at)
           VALUES (?1, ?2, ?3)
           ON CONFLICT(source_name)
           DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at`
        )
        .bind(row.name, JSON.stringify(row.payload), updatedAt)
    );
  }

  await runStatements(database, statements);
}

async function replaceRawRuleRows(database: D1Database, rows: RawRuleRow[], updatedAt: string) {
  await database.prepare(`DELETE FROM ${RAW_RULE_TABLE_NAME}`).run();

  const statements: D1PreparedStatement[] = [];

  for (const row of rows) {
    statements.push(
      database
        .prepare(
          `INSERT INTO ${RAW_RULE_TABLE_NAME} (rule_type, content, updated_at)
           VALUES (?1, ?2, ?3)
           ON CONFLICT(rule_type)
           DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at`
        )
        .bind(row.ruleType, row.content, updatedAt)
    );
  }

  await runStatements(database, statements);
}

async function runStatements(database: D1Database, statements: D1PreparedStatement[]) {
  if (statements.length === 0) {
    return;
  }

  if (typeof database.batch === "function") {
    for (let index = 0; index < statements.length; index += D1_BATCH_SIZE) {
      const chunk = statements.slice(index, index + D1_BATCH_SIZE);
      await database.batch(chunk);
    }
    return;
  }

  for (const statement of statements) {
    await statement.run();
  }
}

async function persistExpandedFeedState(database: D1Database, state: unknown, updatedAt: string) {
  if (!isObject(state)) {
    return;
  }

  await replaceJsonRowsById(database, HASH_TABLE_NAME, asJsonRowsWithId(state.hashes), updatedAt);
  await replaceJsonRowsById(database, URL_TABLE_NAME, asJsonRowsWithId(state.urls), updatedAt);
  await replaceJsonRowsById(database, RULE_TABLE_NAME, asJsonRowsWithId(state.rules), updatedAt);
  await replaceJsonRowsByName(database, SOURCE_TABLE_NAME, asJsonRowsWithName(state.sources), updatedAt);
  await replaceRawRuleRows(database, asRawRuleRows(state.rawRules), updatedAt);
}

async function ensureStateTable(database: D1Database) {
  const existing = initializedDatabases.get(database);
  if (existing) {
    await existing;
    return;
  }

  const initialization = (async () => {
    await database
      .prepare(
        `CREATE TABLE IF NOT EXISTS ${STATE_TABLE_NAME} (
          state_key TEXT PRIMARY KEY,
          payload_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      )
      .run();

    await database
      .prepare(
        `CREATE TABLE IF NOT EXISTS ${HASH_TABLE_NAME} (
          id TEXT PRIMARY KEY,
          payload_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      )
      .run();

    await database
      .prepare(
        `CREATE TABLE IF NOT EXISTS ${URL_TABLE_NAME} (
          id TEXT PRIMARY KEY,
          payload_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      )
      .run();

    await database
      .prepare(
        `CREATE TABLE IF NOT EXISTS ${RULE_TABLE_NAME} (
          id TEXT PRIMARY KEY,
          payload_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      )
      .run();

    await database
      .prepare(
        `CREATE TABLE IF NOT EXISTS ${SOURCE_TABLE_NAME} (
          source_name TEXT PRIMARY KEY,
          payload_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      )
      .run();

    await database
      .prepare(
        `CREATE TABLE IF NOT EXISTS ${RAW_RULE_TABLE_NAME} (
          rule_type TEXT PRIMARY KEY,
          content TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      )
      .run();
  })();

  initializedDatabases.set(database, initialization);

  try {
    await initialization;
  } catch (error) {
    initializedDatabases.delete(database);
    throw error;
  }
}

export function createD1StatePersistenceAdapter<TState>(
  database: D1Database,
  stateKey: string
): StatePersistenceAdapter<TState> {
  return {
    async read() {
      await ensureStateTable(database);

      const row = await database
        .prepare(`SELECT payload_json FROM ${STATE_TABLE_NAME} WHERE state_key = ?1 LIMIT 1`)
        .bind(stateKey)
        .first<{ payload_json?: string }>();

      const snapshot = row && typeof row.payload_json === "string" ? parseJsonOrNull(row.payload_json) : null;

      const [hashes, urls, rules, sources, rawRules] = await Promise.all([
        loadJsonPayloadRows(database, HASH_TABLE_NAME),
        loadJsonPayloadRows(database, URL_TABLE_NAME),
        loadJsonPayloadRows(database, RULE_TABLE_NAME),
        loadJsonPayloadRows(database, SOURCE_TABLE_NAME),
        loadRawRuleMap(database)
      ]);

      if (
        snapshot === null &&
        hashes.length === 0 &&
        urls.length === 0 &&
        rules.length === 0 &&
        sources.length === 0
      ) {
        return null;
      }

      const hydrated = hydrateExpandedFeedState(snapshot, hashes, urls, rules, sources, rawRules);

      return hydrated as TState;
    },

    async write(state: TState) {
      await ensureStateTable(database);

      const updatedAt = new Date().toISOString();

      await persistExpandedFeedState(database, state, updatedAt);

      const compactSnapshot = createCompactFeedSnapshot(state);

      await database
        .prepare(
          `INSERT INTO ${STATE_TABLE_NAME} (state_key, payload_json, updated_at)
           VALUES (?1, ?2, ?3)
           ON CONFLICT(state_key)
           DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at`
        )
        .bind(stateKey, JSON.stringify(compactSnapshot), updatedAt)
        .run();
    }
  };
}
