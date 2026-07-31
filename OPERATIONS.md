# Operations guide

## DNS and keys

Generate an unencrypted RSA key on the target FIPS host so system OpenSSL applies
the active policy:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out mail2026.pem
openssl pkey -in mail2026.pem -pubout -outform DER |
  openssl base64 -A
```

Publish the base64 SubjectPublicKeyInfo at
`mail2026._domainkey.example.com`:

```dns
mail2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=BASE64_PUBLIC_KEY"
```

Install the private key with mode `0600`, owned by `dkim-lite`. Never place it
in the RPM or source archive.

## Rotation

1. Generate a new key and selector and publish its DNS record.
2. Wait at least the DNS TTL and verify the TXT record from production resolvers.
3. Install the key, update `selector` and `private_key`, then run `--check-config`.
4. Send `systemctl reload dkim-lite`. Existing messages retain the old immutable
   key; messages beginning after reload use the new key.
5. Send and independently verify a test message before removing the old DNS key.
6. Retain the old TXT record for the maximum time delayed mail might remain queued.

## Postfix enable and rollback

Configure only authenticated submission or another authorized outgoing path.
Use `milter_default_action = accept`. After `postfix check`, reload Postfix and
send a test message. To roll back, remove `dkim-lite` from `smtpd_milters` and
`non_smtpd_milters`, reload Postfix, then stop the service. Mail continues unsigned.

For a chrooted Postfix, remember that a Unix socket path is resolved below the
queue directory. Loopback TCP avoids that translation. The packaged service makes
`/run/dkim-lite/dkim.sock` mode `0660` with group `postfix`.

## Troubleshooting

Use `journalctl -u dkim-lite -b` and `postfix check`. Logs intentionally contain
neither bodies, header values, private material, nor generated signatures. An
"accepting message unsigned" entry means the message was delivered without a
new signature. Queue saturation or an unavailable daemon is handled by Postfix's
`milter_default_action=accept`.

With SELinux enforcing, inspect `ausearch -m AVC -ts recent`. Do not disable
SELinux to work around a denial; verify the socket label, service domain, and
Postfix access and add a narrowly scoped local policy only if the target policy
requires it.

## Offline build and promotion

Run `packaging/make-source.sh VERSION` on a connected release workstation. Copy
the tarball and `.sha256` into the isolated build environment, verify the digest,
and build each RPM with networking disabled. Promote the source RPM, binary RPM,
and SHA-256 manifest together. Each RHEL major version must build on that release
so glibc and OpenSSL linkage are native to it.

Dependency refresh is deliberate: update exact versions, run `cargo vendor
--locked vendor`, inspect licenses and diffs, run the full test/fuzz matrix, and
record new archive checksums. The separate `fuzz/vendor` tree is never included
in production source archives.
