#![no_main]

use dkim_lite::dkim::BodyCanonicalizer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut body = BodyCanonicalizer::default();
    for chunk in data.chunks(17) {
        body.update(chunk);
    }
    let _ = body.finish();
});
