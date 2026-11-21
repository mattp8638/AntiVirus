// Seal a secret to a backup agent's X25519 public key, in the browser (device backup).
// Must match backup/crates/protocol/src/seal.rs exactly:
//   key = HKDF-SHA256(X25519(eph, agent), salt = epk || agentPk, info = "fenrir-agent-seal-v1")
//   ct  = AES-256-GCM(key, random 12-byte nonce)
// The server only ever sees the result.

export interface Sealed {
  v: 1;
  epk: string;
  nonce: string;
  ct: string;
}

const enc = new TextEncoder();

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function sealSupported(): boolean {
  return typeof crypto !== "undefined" && !!crypto.subtle;
}

export async function seal(agentPublicB64: string, plaintext: string): Promise<Sealed> {
  const subtle = crypto.subtle;
  const agentPk = unb64(agentPublicB64);
  if (agentPk.length !== 32) throw new Error("agent public key must be 32 bytes");
  const agentKey = await subtle.importKey("raw", agentPk, { name: "X25519" }, false, []);
  const eph = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const epk = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const shared = await subtle.deriveBits({ name: "X25519", public: agentKey }, eph.privateKey, 256);
  const salt = new Uint8Array(64);
  salt.set(epk, 0);
  salt.set(agentPk, 32);
  const hkdfKey = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aesKey = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("fenrir-agent-seal-v1") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, enc.encode(plaintext)));
  return { v: 1, epk: b64(epk), nonce: b64(nonce), ct: b64(ct) };
}

/** A recovery key file, generated in the browser so it never reaches the server. */
export function newRecoveryKey(): { repoId: string; slotId: string; fileContents: string } {
  const repoId = crypto.randomUUID();
  const slotId = crypto.randomUUID();
  const key = crypto.getRandomValues(new Uint8Array(32));
  const file = {
    format: "fenrir-recovery-key",
    version: 1,
    repo_id: repoId,
    slot_id: slotId,
    key: b64(key),
  };
  return { repoId, slotId, fileContents: JSON.stringify(file, null, 2) + "\n" };
}
