# Signing-only benchmark against Rspamd

Run on 2026-07-31 (America/New_York). These results are a focused engineering
comparison, not a claim about Rspamd's normal full filtering workload.

## Result

Each value is the median of three complete trials. Latency percentiles are the
median of the three trial-level percentiles.

| Body | Concurrency | Signer | Messages/s | Median latency | p95 latency | Throughput ratio |
|---:|---:|---|---:|---:|---:|---:|
| 1 KiB | 1 | dkim-lite | 1,940.71 | 0.422 ms | 0.528 ms | 1.9x |
| 1 KiB | 1 | Rspamd | 1,018.12 | 0.935 ms | 1.308 ms | baseline |
| 1 KiB | 8 | dkim-lite | 3,160.44 | 2.185 ms | 3.140 ms | 1.4x |
| 1 KiB | 8 | Rspamd | 2,318.06 | 3.104 ms | 5.721 ms | baseline |
| 100 KiB | 1 | dkim-lite | 699.94 | 1.161 ms | 1.255 ms | 10.4x |
| 100 KiB | 1 | Rspamd | 67.10 | 14.144 ms | 17.673 ms | baseline |
| 100 KiB | 8 | dkim-lite | 1,921.98 | 2.913 ms | 4.666 ms | 10.8x |
| 100 KiB | 8 | Rspamd | 178.63 | 45.229 ms | 71.385 ms | baseline |
| 1 MiB | 1 | dkim-lite | 110.44 | 8.127 ms | 8.647 ms | 16.8x |
| 1 MiB | 1 | Rspamd | 6.57 | 143.700 ms | 172.493 ms | baseline |
| 1 MiB | 8 | dkim-lite | 369.73 | 17.542 ms | 19.892 ms | 21.6x |
| 1 MiB | 8 | Rspamd | 17.09 | 217.605 ms | 859.499 ms | baseline |

The gap increases with body size. `dkim-lite` streams only relaxed body
canonicalization and SHA-256 state. Rspamd still routes the message through its
general task and MIME infrastructure even when its documented `skip_process`
signing-only setting is selected.

## Environment

- Fedora Linux 44, Linux 7.1.4-200.fc44.x86_64
- Intel Core i7-1165G7, 8 logical CPUs
- OpenSSL 3.5.7
- `dkim-lite 0.2.0`, native release build linked to Fedora's `libssl.so.3`,
  `libcrypto.so.3`, and glibc
- Official `docker.io/rspamd/rspamd:3.13.2` image under rootless Podman, using
  host networking so both signers received direct loopback TCP traffic
- One shared 2048-bit RSA key, selector `benchmark`, domain `example.com`

Rspamd used one proxy worker and its default four normal workers. `dkim-lite`
used its normal eight worker threads on this host. This compares the products'
current default concurrency models, not one isolated crypto operation.

## Signing-only Rspamd configuration

The reproducible container entrypoint is
[`rspamd-signing-only-entrypoint.sh`](rspamd-signing-only-entrypoint.sh). It:

- disables every configured Lua module except `dkim_signing` and its required
  `dkim` engine;
- limits the internal C filter list to `dkim`;
- disables the controller worker; and
- applies Rspamd's documented authenticated `sign_only` setting with only
  `DKIM_SIGNED` enabled and `flags = ["skip_process"]`.

`rspamadm configtest` returned `syntax OK`. `rspamadm configdump -m` reported
`dkim_signing`, `dkim`, `settings`, and `bayes_expiry` as loaded. `settings` is
needed to select the signing-only route; Bayes is a core facility that remains
loaded but was skipped for benchmark messages. Rspamd's task log confirmed
`settings_id: sign_only`, exactly one result (`DKIM_SIGNED`), and zero DNS
requests.

Rspamd's own documentation recommends this `skip_process` settings pattern for
[DKIM-signing-only operation](https://docs.rspamd.com/modules/dkim_signing/).
The module disabling convention and effective-configuration inspection follow
the [configuration fundamentals](https://docs.rspamd.com/guides/configuration/fundamentals/)
and [`rspamadm` configuration documentation](https://docs.rspamd.com/administration/rspamadm/configuration/).

## Method

The reusable client is [`benchmark_milter.py`](benchmark_milter.py). For every
message it sends a complete milter transaction, waits for final acceptance, and
requires an add/insert action for `DKIM-Signature`; an unsigned fail-open result
causes the trial to fail. It uses the milter no-reply negotiation flags each
signer accepts and sets `TCP_NODELAY`.

One connection is reused per concurrent client, matching normal milter use and
excluding repeated TCP handshakes. Per-message latency starts immediately before
`MAIL FROM` and ends after the final accept response. Throughput uses total wall
time, including each worker's initial connection and negotiation. Each signer
processed 17,880 measured messages across the matrix, plus warmups.

Trial sizes were:

| Body | Concurrency 1 | Concurrency 8 | Warmup per trial |
|---:|---:|---:|---:|
| 1 KiB | 1,500 | 3,000 | 20 |
| 100 KiB | 400 | 800 | 10 |
| 1 MiB | 100 | 160 | 5 |

The benchmark also exposed a TCP transport defect in `dkim-lite`: without
`TCP_NODELAY`, synchronous milter command responses incurred delayed-ACK stalls.
The daemon now enables it on accepted TCP sockets, with a regression test.

## Caveats

- Rspamd ran in its official container userland while `dkim-lite` ran natively;
  both used the same Fedora kernel, CPU, direct host-loopback path, message
  stream, and private key.
- Rspamd is a general mail-processing engine. Disabling rules does not turn it
  into a body-streaming signer internally, so the large-message result reflects
  that architectural difference.
- No CPU affinity was applied because rootless Podman's cpuset controller was
  unavailable. The host was otherwise idle and the three trials were stable.
- Post-workload memory observations were about 8 MiB RSS for `dkim-lite` versus
  462.5 MiB of container cgroup memory for Rspamd. These are indicative only:
  the accounting methods differ and Rspamd retains allocator/parser caches.
- This benchmark does not replace the independent signature-correctness,
  Postfix, FIPS, or denial-of-service test suites.
