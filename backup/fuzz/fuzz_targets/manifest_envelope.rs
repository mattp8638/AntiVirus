#![no_main]
//! Envelope + manifest body parsing and validation, as done after
//! decryption. Signature verification is exercised with a fixed key.
use core_format::manifest::{verify_envelope, Envelope, ManifestBody, ManifestSigner};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = serde_json::from_slice::<Envelope>(data) {
        let signer = ManifestSigner::from_seed([7; 32]);
        let _ = verify_envelope(&env, &signer.verifying_key(), &uuid::Uuid::nil());
    }
    if let Ok(body) = serde_json::from_slice::<ManifestBody>(data) {
        let _ = body.validate();
        let _ = body.chunk_ids();
    }
});
