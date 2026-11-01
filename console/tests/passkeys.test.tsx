import { afterEach, expect, test, vi } from "vitest";
import { addPasskey, passkeyResponse } from "../src/passkeys";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

const bytes = (...values: number[]) => new Uint8Array(values).buffer;
const text = (buffer: ArrayBuffer) => Array.from(new Uint8Array(buffer));

function serverReplies(...bodies: unknown[]) {
  const sent: { url: string; body: any }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    sent.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(JSON.stringify(bodies.shift() ?? {}), { status: 200 });
  }));
  return sent;
}

test("a passkey sign-in sends the browser binary fields and returns them as base64url", async () => {
  const sent = serverReplies({ token: "signed", publicKey: { challenge: "-_8", rpId: "fenrir.test", userVerification: "required", allowCredentials: [] } });
  const get = vi.fn(async (options: CredentialRequestOptions) => {
    expect(text(options.publicKey!.challenge as ArrayBuffer)).toEqual([0xfb, 0xff]);
    return { id: "cred", rawId: bytes(1, 2, 3), type: "public-key",
             response: { clientDataJSON: bytes(0xfb), authenticatorData: bytes(0xff, 0xfe), signature: bytes(9), userHandle: null } };
  });
  vi.stubGlobal("navigator", { credentials: { get } });
  const result = await passkeyResponse();
  expect(sent[0].url).toContain("/api/console/auth/passkey/options");
  expect(result).toEqual({ token: "signed", credential: { id: "cred", rawId: "AQID", type: "public-key",
    response: { clientDataJSON: "-w", authenticatorData: "__4", signature: "CQ", userHandle: "" } } });
});

test("adding a passkey converts the user id and existing keys, then registers the result", async () => {
  const sent = serverReplies(
    { token: "signed", publicKey: { challenge: "AA", user: { id: "dXNy", name: "a@b", displayName: "A" }, excludeCredentials: [{ type: "public-key", id: "AQ" }] } },
    { id: "pk_1", name: "Laptop" });
  const create = vi.fn(async (options: CredentialCreationOptions) => {
    expect(new TextDecoder().decode(options.publicKey!.user.id as ArrayBuffer)).toBe("usr");
    expect(text(options.publicKey!.excludeCredentials![0].id as ArrayBuffer)).toEqual([1]);
    return { id: "new", rawId: bytes(7), type: "public-key",
             response: { clientDataJSON: bytes(1), attestationObject: bytes(2), getTransports: () => ["internal"] } };
  });
  vi.stubGlobal("navigator", { credentials: { create } });
  await addPasskey("Laptop");
  expect(sent[1].url).toContain("/api/console/auth/passkeys");
  expect(sent[1].body).toEqual({ token: "signed", name: "Laptop", credential: { id: "new", rawId: "Bw", type: "public-key",
    response: { clientDataJSON: "AQ", attestationObject: "Ag", transports: ["internal"] } } });
});

test("a cancelled passkey prompt says so in plain words", async () => {
  serverReplies({ token: "signed", publicKey: { challenge: "AA" } });
  vi.stubGlobal("navigator", { credentials: { get: async () => { throw Object.assign(new Error("x"), { name: "NotAllowedError" }); } } });
  await expect(passkeyResponse()).rejects.toThrow("cancelled or timed out");
});
