import test from "node:test";
import assert from "node:assert/strict";
import { expectArray, safeArray } from "../src/data-shapes.ts";

test("valid collection results are preserved", () => {
  const rows = [{ id: "first" }, { id: "second" }];
  assert.strictEqual(expectArray(rows, "grc/records"), rows);
  assert.deepEqual(expectArray([], "network/monitors"), []);
});

test("unexpected successful JSON is rejected instead of causing a React .map crash", () => {
  for (const unexpected of [null, undefined, {}, { items: [] }, { detail: "unauthorised" }, "OK", 12]) {
    assert.throws(() => expectArray(unexpected, "backup/plans"), /Unable to load backup\/plans: expected a list/);
  }
});

test("optional nested Graph results cannot pass an object to Table", () => {
  const rows = [{ displayName: "Example" }];
  assert.strictEqual(safeArray(rows), rows);
  assert.deepEqual(safeArray(null), []);
  assert.deepEqual(safeArray({ value: rows }), []);
  assert.deepEqual(safeArray("unavailable"), []);
});
