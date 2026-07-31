# Fuzz testing

This workspace is deliberately separate from the production crate and vendor
bundle. On a connected development system, install `cargo-fuzz`, refresh this
workspace's lock/vendor bundle, and run each target for a fixed interval:

```sh
cargo install cargo-fuzz --locked
cd fuzz
cargo fuzz run milter_frame -- -max_total_time=300
cargo fuzz run header -- -max_total_time=300
cargo fuzz run body -- -max_total_time=300
```

Retain minimized failures under `fuzz/artifacts/` until they have been converted
to deterministic regression tests. Fuzz dependencies must not be copied into
the production `vendor/` directory or RPM source archive.
