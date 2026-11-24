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

/**
 * Decrypt files a machine encrypted for this browser (Fenrir-Backup docs/design/file-download.md):
 * the content key is sealed to the one-time public key; the stream is (u32 BE length || AES-256-GCM frame)*,
 * frame i with nonce = 4 zero bytes || i (u64 BE) and AAD = [1 if last frame else 0].
 */
async function decryptDownload(privateKey: CryptoKey, publicKey: Uint8Array, header: { sealed_key: Sealed }, stream: ArrayBuffer): Promise<Uint8Array> {
  const subtle = crypto.subtle;
  const s = header.sealed_key;
  const epk = unb64(s.epk);
  const eph = await subtle.importKey("raw", epk as BufferSource, { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: eph } as any, privateKey, 256);
  const salt = new Uint8Array(64);
  salt.set(epk, 0);
  salt.set(publicKey, 32);
  const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const k = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("fenrir-agent-seal-v1") }, hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const raw = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(s.nonce) as BufferSource }, k, unb64(s.ct) as BufferSource));
  const key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
  const view = new DataView(stream);
  const parts: Uint8Array[] = [];
  let pos = 0, i = 0, total = 0;
  while (pos < stream.byteLength) {
    if (pos + 4 > stream.byteLength) throw new Error("the download is incomplete");
    const len = view.getUint32(pos);
    if (pos + 4 + len > stream.byteLength) throw new Error("the download is incomplete");
    const ct = new Uint8Array(stream, pos + 4, len);
    pos += 4 + len;
    const iv = new Uint8Array(12);
    new DataView(iv.buffer).setBigUint64(4, BigInt(i));
    const last = pos === stream.byteLength ? 1 : 0;
    const p = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: new Uint8Array([last]) }, key, ct));
    parts.push(p);
    total += p.length;
    i++;
  }
  if (i === 0) throw new Error("the download is empty");
  const out = new Uint8Array(new ArrayBuffer(total));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** A one-time key pair for receiving files from a machine. Only the public key leaves the browser. */
export async function downloadKey(): Promise<{ publicB64: string; decrypt: (header: { sealed_key: Sealed }, stream: ArrayBuffer) => Promise<Uint8Array> }> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  const pk = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { publicB64: b64(pk), decrypt: (header, stream) => decryptDownload(pair.privateKey, pk, header, stream) };
}
