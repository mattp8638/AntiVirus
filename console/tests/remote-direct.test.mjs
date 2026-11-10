import test from "node:test";
import assert from "node:assert/strict";
import { Reassembler, splitChunks, directAllowed } from "../src/remote-direct.ts";

test("frames split by the agent come back whole", () => {
  for (const size of [0, 1, 15999, 16000, 16001, 80077]) {
    const frame = new Uint8Array(size).map((_, i) => (i * 7) & 0xff);
    const r = new Reassembler();
    let out = null;
    for (const part of splitChunks(9, frame)) out = r.add(part) ?? out;
    assert.ok(out, `size ${size}`);
    assert.deepEqual(Array.from(out), Array.from(frame));
  }
});

test("a gap drops the frame and the next one still decodes", () => {
  const parts = splitChunks(1, new Uint8Array(48000));
  const r = new Reassembler();
  assert.equal(r.add(parts[0]), null);
  assert.equal(r.add(parts[2]), null);
  const next = splitChunks(2, new TextEncoder().encode("hi"));
  assert.equal(new TextDecoder().decode(r.add(next[0])), "hi");
});

test("only screen and ordinary input go direct", () => {
  assert.ok(directAllowed({ ch: "screen", t: "ack" }));
  assert.ok(directAllowed({ ch: "input", t: "mm" }));
  for (const m of [{ ch: "input", t: "cad" }, { ch: "input", t: "lock" }, { ch: "input", t: "clip" }, { ch: "term", t: "open" },
                   { ch: "files", t: "list" }, { ch: "chat", t: "msg" }, { ch: "sys", t: "end" }, { ch: "rtc", t: "offer" }]) {
    assert.equal(directAllowed(m), false, JSON.stringify(m));
  }
});
