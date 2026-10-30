// Passkeys (WebAuthn): the browser talks to the phone, laptop or security key; the server checks what comes back.
// The server sends and expects binary fields as base64url, so this file only converts and calls navigator.credentials.
import { api } from "./api";

type Json = Record<string, unknown>;

export interface PasskeyAssertion {
  token: string;
  credential: Json;
}

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

function toBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  return bytes.buffer;
}

function toBase64url(buffer: ArrayBuffer | null | undefined): string {
  if (!buffer) return "";
  let text = "";
  new Uint8Array(buffer).forEach((b) => { text += String.fromCharCode(b); });
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Cancelled or timed out: say so plainly rather than "NotAllowedError: The operation either timed out or was not allowed".
function explain(err: unknown): Error {
  const name = (err as { name?: string })?.name;
  if (name === "NotAllowedError" || name === "AbortError") return new Error("The passkey request was cancelled or timed out.");
  if (name === "InvalidStateError") return new Error("This device already has a passkey for your account.");
  if (name === "SecurityError") return new Error("Passkeys need this console to be opened at its HTTPS address.");
  return err instanceof Error ? err : new Error(String(err));
}

/** Registers a new passkey on this device. The server needs a recent password check first (the api helper asks). */
export async function addPasskey(name: string): Promise<void> {
  const options = await api<{ token: string; publicKey: Json & { challenge: string; user: Json & { id: string }; excludeCredentials: { id: string; type: string }[] } }>(
    "auth/passkeys/options", { body: {} });
  const publicKey = {
    ...options.publicKey,
    challenge: toBuffer(options.publicKey.challenge),
    user: { ...options.publicKey.user, id: toBuffer(options.publicKey.user.id) },
    excludeCredentials: options.publicKey.excludeCredentials.map((c) => ({ ...c, id: toBuffer(c.id) })),
  } as unknown as PublicKeyCredentialCreationOptions;
  let created: PublicKeyCredential;
  try {
    created = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
  } catch (err) {
    throw explain(err);
  }
  const response = created.response as AuthenticatorAttestationResponse;
  await api("auth/passkeys", { body: { token: options.token, name, credential: {
    id: created.id, rawId: toBase64url(created.rawId), type: created.type,
    response: { clientDataJSON: toBase64url(response.clientDataJSON), attestationObject: toBase64url(response.attestationObject),
                transports: typeof response.getTransports === "function" ? response.getTransports() : [] } } } });
}

/** Asks this device for a passkey response the server can check, for signing in or confirming who you are. */
export async function passkeyResponse(): Promise<PasskeyAssertion> {
  const options = await api<{ token: string; publicKey: Json & { challenge: string } }>("auth/passkey/options", { body: {} });
  const publicKey = { ...options.publicKey, challenge: toBuffer(options.publicKey.challenge) } as unknown as PublicKeyCredentialRequestOptions;
  let got: PublicKeyCredential;
  try {
    got = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
  } catch (err) {
    throw explain(err);
  }
  const response = got.response as AuthenticatorAssertionResponse;
  return { token: options.token, credential: {
    id: got.id, rawId: toBase64url(got.rawId), type: got.type,
    response: { clientDataJSON: toBase64url(response.clientDataJSON), authenticatorData: toBase64url(response.authenticatorData),
                signature: toBase64url(response.signature), userHandle: toBase64url(response.userHandle) } } };
}
