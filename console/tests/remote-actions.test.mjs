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

test("the remote screen keeps its shape in every size mode", async () => {
  const { screenDisplaySize } = await import("../src/remote-actions.ts");
  const ratio = (s) => s.w / s.h;
  for (const remote of [{ w: 1920, h: 1080 }, { w: 1024, h: 768 }, { w: 5120, h: 1440 }, { w: 1280, h: 1024 }]) {
    for (const mode of ["fit", "actual", "1920x1080", "1600x900", "1366x768", "1280x720"]) {
      const shown = screenDisplaySize(mode, remote, { w: 1500, h: 700 });
      assert.ok(Math.abs(ratio(shown) - remote.w / remote.h) < 0.01, `${mode} ${remote.w}x${remote.h} -> ${shown.w}x${shown.h}`);
    }
  }
});

test("fixed sizes fit inside exactly that box; fit fills the window; actual is 1:1", async () => {
  const { screenDisplaySize } = await import("../src/remote-actions.ts");
  assert.deepEqual(screenDisplaySize("1280x720", { w: 1920, h: 1080 }, { w: 300, h: 300 }), { w: 1280, h: 720, scale: 1280 / 1920 });
  const square = screenDisplaySize("1920x1080", { w: 1280, h: 1024 }, { w: 300, h: 300 });
  assert.ok(square.w <= 1920 && square.h === 1080);
  const fit = screenDisplaySize("fit", { w: 1920, h: 1080 }, { w: 1000, h: 1000 });
  assert.equal(fit.w, 1000);
  assert.deepEqual(screenDisplaySize("actual", { w: 1024, h: 768 }, { w: 10, h: 10 }), { w: 1024, h: 768, scale: 1 });
});
