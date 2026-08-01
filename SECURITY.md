# Security model

`dkim-lite` is a signing boundary for already-authorized outgoing mail. It does
not authenticate senders and must not be attached to an unrestricted inbound
SMTP path.

The daemon retains an immutable configuration and RSA key per active message,
streams body hashing, and stores at most 1,000 headers totaling 1 MiB. Individual
milter packets are limited to 1 MiB, connections to 60 seconds, workers to 32,
and the pending connection queue to twice the worker count. Signing or parsing
failure accepts the original message without adding a partial signature.

Private keys must be unencrypted RSA PEM/PKCS#8, 2048–4096 bits, mode `0600`, and
owned by the service account. Keys remain in process memory while active and are
released after the last configuration/message reference. Memory locking and HSM
support are outside version 1.

The production build uses the platform OpenSSL library. It never enables the
OpenSSL crate's bundled-source feature. `require_fips=true` is the default and
requires both kernel and OpenSSL FIPS state; setting it false is an explicit
operator decision for non-FIPS Linux systems.

The `generate-key` command uses system OpenSSL EVP key generation, writes an
unencrypted PKCS#8 key atomically with mode `0600`, and refuses replacement of
an existing pathname. Its output contains only the destination path and public
DNS material. Operators remain responsible for private-key ownership, secure
staging-file removal, DNS publication, and rotation.

Report vulnerabilities through this repository's private GitHub vulnerability
reporting flow: open the **Security** tab, select **Advisories**, then select
**Report a vulnerability**. If that control is unavailable, open a public issue
containing only a request for private contact; do not disclose vulnerability
details there. Never include production message contents, private keys, or other
credentials in a report.
