#![no_main]
//! Chunk and manifest container decoding with a fixed key: must reject,
//! never panic or over-allocate, on arbitrary input.
use core_format::chunk::{decode_chunk, ChunkId};
use core_format::crypto::SecretKey;
use core_format::manifest::open_envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let k = SecretKey::from_bytes([1; 32]);
    let id = SecretKey::from_bytes([2; 32]);
    let _ = decode_chunk(&k, &id, &ChunkId([3; 32]), data);
    let _ = open_envelope(&uuid::Uuid::nil(), &k, data);
});
