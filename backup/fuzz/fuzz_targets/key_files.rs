#![no_main]
//! Key slot and recovery key parsing. Does not run the KDF on fuzzed
//! parameters (that is bounded by KdfParams::check_bounds, tested separately).
use core_format::keys::{KeySlot, RecoveryKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = RecoveryKey::from_file_contents(s);
    }
    if let Ok(slot) = serde_json::from_slice::<KeySlot>(data) {
        if let Some(k) = &slot.kdf {
            let _ = k.params.check_bounds();
        }
        if let Ok(rk) = RecoveryKey::generate(uuid::Uuid::nil()) {
            let _ = slot.unwrap_with_recovery_key(&uuid::Uuid::nil(), &rk);
        }
    }
});
