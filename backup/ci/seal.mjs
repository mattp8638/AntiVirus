// Seal a secret to an agent's public key, exactly as the web UI does
// (ui/src/seal.ts). Used by CI to drive the API without a browser.
//   node ci/seal.mjs <agent public key, base64> <plaintext>  -> sealed JSON
const [pubB64, plaintext] = process.argv.slice(2);
if (!pubB64 || plaintext === undefined) {
  console.error("usage: node ci/seal.mjs <agent-public-key-b64> <plaintext>");
  process.exit(2);
}
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString("base64");
const agentPk = new Uint8Array(Buffer.from(pubB64, "base64"));
if (agentPk.length !== 32) throw new Error("agent public key must be 32 bytes");
const agentKey = await subtle.importKey("raw", agentPk, { name: "X25519" }, false, []);
const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
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
const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, enc.encode(plaintext)));
process.stdout.write(JSON.stringify({ v: 1, epk: b64(epk), nonce: b64(nonce), ct: b64(ct) }));
