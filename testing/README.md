# Qualification matrix

Run the release suite in clean FIPS-enabled RHEL-compatible 8, 9, and 10 guests.
Record whether each guest is RHEL or Rocky and retain the commands and artifact
checksums in the release report.

Required checks:

1. Confirm `/proc/sys/crypto/fips_enabled` is `1` and the system crypto policy is
   FIPS. Confirm `require_fips=true` succeeds and fails after booting a non-FIPS
   snapshot; confirm `require_fips=false` succeeds there.
2. Run tests, clippy, and release builds with `--locked --offline`. Confirm `ldd`
   resolves only the release's system `libssl`, `libcrypto`, and glibc.
3. Build and install the binary/source RPMs, run `rpm -V`, and confirm the service
   is disabled until configured.
4. Exercise Postfix through Unix and loopback TCP listeners: normal signing,
   existing signatures, malformed input, abort/reuse, restart, fail-open, partial
   packets, concurrent clients, queue exhaustion, and SIGHUP key rotation.
5. Publish the test public key through an isolated DNS server and require both
   OpenDKIM and Rspamd to report a valid DKIM signature.
6. Run with SELinux enforcing, verify service/key/socket ownership, and require no
   new AVC denials.

The `rocky10-fips.ks` and XML definition reproduce the Rocky 10 qualification VM.
They are test infrastructure and are excluded from production source archives.
The checked-in Kickstart templates lock all password authentication; add an
operator-controlled `sshkey --username=dkim-test ...` entry to a private working copy
before installing a guest. Never commit a VM password or private key.
Completed qualification results and artifact digests are recorded in
[`VALIDATION.md`](VALIDATION.md).

The repeatable signing-only performance comparison and its Rspamd configuration
are documented in [`BENCHMARK-RSPAMD.md`](BENCHMARK-RSPAMD.md).
