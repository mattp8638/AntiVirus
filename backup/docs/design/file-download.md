# Design note: downloading restored files to the browser

Status: implemented.

File-level restore could write files to a folder on a machine. A download
sends them to the person asking, in the browser, without the server ever
seeing them.

1. The browser makes a one-time X25519 key pair (WebCrypto, private key not
   extractable) and sends only the public key with the request
   (`POST /api/images/{id}/download-files`: machine, volume, paths,
   `recipient`).
2. The machine restores the files into a private temporary folder in its
   state directory, packs them as a tar archive (POSIX ustar, PAX records
   for long or non-ASCII names) and deletes the folder afterwards.
3. It picks a random 256-bit content key, seals it to the browser's public
   key with the scheme used for every secret (X25519, HKDF-SHA256 with info
   `fenrir-agent-seal-v1`, AES-256-GCM), and encrypts the archive in frames:
   `AES-256-GCM(key, nonce = 0u32 || index u64 BE, aad = [last ? 1 : 0])`
   over at most 1 MiB each, stored as `u32 BE length || frame`. Numbered
   nonces stop frames being reordered or repeated; the last-frame flag stops
   a truncated stream decrypting as complete.
4. The stream is uploaded to the server in batches with their offset
   (`POST /api/agent/jobs/{id}/download?offset=`), so a retried request does
   nothing and a gap is refused; only the job's own machine can upload, and
   only while the job runs. The job's result carries the sealed key.
5. The browser fetches the stream (`GET /api/jobs/{id}/download`), opens the
   content key with its private key, decrypts the frames and saves the tar.
   The server deletes streams after 24 hours.

Limit: 4 GiB per download (the browser holds it in memory); larger restores
go to a folder on a machine.

Tests: frame round trip and refusal of altered, cut or wrongly keyed
streams; the tar is read back by the system's `tar` (long names) and the
encrypted upload decrypts to the same archive; the server relay (offsets,
retries, gaps, other machines, not before the job finishes, purge); and in
CI the browser's TypeScript decrypts a stream the Rust code produced.
