#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dkim_lite::milter::fuzz_milter_frame(data);
});
