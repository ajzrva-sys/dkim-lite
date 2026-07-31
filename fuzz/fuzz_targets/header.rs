#![no_main]

use dkim_lite::dkim::{canonicalize_header, Header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len().min(128);
    let _ = Header::new(&data[..split], &data[split..]);
    let _ = canonicalize_header(&data[..split], &data[split..]);
});
