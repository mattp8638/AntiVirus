import test from "node:test";
import assert from "node:assert/strict";
import { cadResult } from "../src/remote-actions.ts";

test("an acknowledgement confirms a request, never a Windows sign-in", () => {
  const reply = { ch: "sys", t: "action.result", action: "cad", req: "click-1", ok: true,
    message: "Ctrl+Alt+Del requested for this Windows session." };
  assert.deepEqual(cadResult(reply, "click-1"), { tone: "notice", message: reply.message });
});

test("policy and service failures remain visible to the technician", () => {
  const reply = { ch: "sys", t: "action.result", action: "cad", req: "click-1", ok: false,
    message: "Ctrl+Alt+Del could not be sent: blocked by Group Policy" };
  assert.deepEqual(cadResult(reply, "click-1"), { tone: "error", message: reply.message });
  assert.equal(cadResult({ ...reply, message: null }, "click-1").tone, "error");
  assert.equal(cadResult({ ...reply, ok: true, message: null }, "click-1").tone, "error");
  assert.equal(cadResult({ ...reply, ok: "true" }, "click-1").tone, "error");
});

test("late, unrelated and unsolicited results cannot complete a new request", () => {
  const reply = { ch: "sys", t: "action.result", action: "cad", req: "old-click", ok: true };
  assert.equal(cadResult(reply, "new-click"), null);
  assert.equal(cadResult(reply, null), null);
  assert.equal(cadResult({ ...reply, action: "reboot" }, "old-click"), null);
  assert.equal(cadResult({ ch: "sys", t: "error", message: "Something unrelated" }, "old-click"), null);
});

test("a legacy helper response cannot certify the silently ignored SendSAS call", () => {
  const result = cadResult({ ch: "sys", t: "notice", message: "Ctrl+Alt+Del sent" }, "click-1");
  assert.equal(result.tone, "warning");
  assert.match(result.message, /update the Windows agent/i);
  const failure = cadResult({ ch: "sys", t: "error", message: "Ctrl+Alt+Del could not be sent" }, "click-1");
  assert.equal(failure.tone, "error");
});
