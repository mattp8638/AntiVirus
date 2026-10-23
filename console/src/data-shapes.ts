/** Runtime validation for collection endpoints.
 * TypeScript generics describe expected responses but do not validate JSON.
 * Fail visibly if a backend unexpectedly returns an object or error envelope.
 */
export function expectArray<T = unknown>(value: unknown, endpoint: string): T[] {
  if (Array.isArray(value)) return value as T[];
  const received = value === null ? "null" : typeof value;
  throw new Error(`Unable to load ${endpoint}: expected a list but received ${received}. Check the API response and server logs.`);
}

/** For optional nested arrays in a successful detail response, e.g. cached Graph snapshots. */
export function safeArray<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : [];
}
