#![no_main]
use core_format::partition::{detect_sector_size, read_table};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let v = data.to_vec();
    let n = v.len() as u64;
    let ss = detect_sector_size(&v, n);
    let _ = read_table(&v, n, ss);
    let _ = read_table(&v, n.saturating_mul(8), 512);
    let _ = core_format::fsdetect::detect(&v, 0, n);
});
