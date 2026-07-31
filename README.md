# dkim-lite

`dkim-lite` is an outgoing-only Postfix milter that adds RFC 6376
RSA-SHA256 DKIM signatures. It intentionally does not scan mail, verify inbound
signatures, query DNS, parse MIME, or implement ARC/SPF/DMARC.

The source is intended to build on Linux systems with a usable system OpenSSL.
The supported production deployment targets for version 1 are RHEL 8, 9, and 10.
The OpenSSL `vendored` Cargo feature must never be enabled.

## Build

Install the RHEL Rust toolset, GCC, pkg-config, and OpenSSL development files.
RHEL 8 distributes Rust as a module; RHEL 9 and 10 distribute it as packages.

```sh
# RHEL 8
dnf module install rust-toolset

# RHEL 9/10
dnf install rust-toolset

dnf install gcc pkgconf-pkg-config openssl-devel
cargo build --release --locked --offline
```

Cargo is configured to use `vendor/`; builds do not contact crates.io. To refresh
dependencies on a connected development system after deliberately updating
`Cargo.lock`, run `cargo vendor --locked vendor` and review the resulting source
and checksums.

## Configure

```ini
domain=example.com
selector=mail2026
private_key=/etc/dkim-lite/mail2026.pem
listen=unix:/run/dkim-lite/dkim.sock
require_fips=true
```

These settings and comments are the only accepted syntax. `require_fips` is
optional and defaults to `true`; when enabled, both the Linux kernel and system
OpenSSL must report active FIPS mode. Set it to `false` explicitly for a non-FIPS
Linux deployment. The TCP alternative is a numeric loopback
address such as `tcp:127.0.0.1:8891`. The domain and selector are lowercased. The
key must be an unencrypted 2048- or 4096-bit RSA PEM/PKCS#8 private key.

Install the key so only the signer account can read it:

```sh
install -o dkim-lite -g dkim-lite -m 0600 mail2026.pem /etc/dkim-lite/mail2026.pem
/usr/sbin/dkim-lite --check-config --config /etc/dkim-lite/dkim-lite.conf
systemctl enable --now dkim-lite
```

`SIGHUP` atomically reloads the domain, selector, and key. Changing the listener
requires a restart. If reload validation fails, the previous configuration stays
active.

## Postfix

Route only authenticated/authorized outgoing mail through this signer. For a Unix
socket, Postfix syntax is:

```ini
milter_protocol = 6
milter_default_action = accept
smtpd_milters = unix:/run/dkim-lite/dkim.sock
non_smtpd_milters = unix:/run/dkim-lite/dkim.sock
```

If Postfix is chrooted, its Unix pathname is relative to the Postfix queue
directory. A loopback TCP deployment avoids that path translation:

```ini
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891
```

Do not place the signer on an unrestricted inbound SMTP service. Configure these
parameters on the submission service or another path that has already authenticated
the sender.

## Signing and failure behavior

The signer requires exactly one syntactically usable `From` header whose domain
exactly matches `domain`. It uses relaxed/relaxed canonicalization, oversigns
`From`, signs a conservative fixed header set, and preserves existing DKIM
signatures. Bodies are hashed incrementally and are not stored in memory.

Malformed or ineligible messages and all signing failures are logged and accepted
without modification. No message content, key material, or signature value is
written to logs. Postfix should also use `milter_default_action = accept` to retain
the same availability policy if the daemon is unavailable.

## Verification and fuzzing

`cargo test --locked --offline` includes RFC 6376 canonicalization, independent
OpenSSL signature verification, binary input, milter framing, abort/reuse, and
resource-limit tests. Production qualification additionally verifies messages
with OpenDKIM and Rspamd in the target VM. The separately locked `fuzz/` workspace
contains framing, header, and body targets and has its own vendor bundle.

## RPM and operations

Create `dkim-lite-0.1.0.tar.gz` with the crate root—including `vendor/`—as its top
directory and build `packaging/dkim-lite.spec` independently inside clean RHEL 8,
9, and 10 build roots. The resulting RPM links to each release's system OpenSSL and
glibc. Always build with networking disabled to enforce offline reproducibility.
Use `packaging/make-source.sh` to create a deterministic production source archive
and checksum; it excludes fuzz dependencies and VM definitions. See
[`OPERATIONS.md`](OPERATIONS.md) for DNS, rotation, rollback, troubleshooting, and
release promotion and [`SECURITY.md`](SECURITY.md) for the threat model and limits.
