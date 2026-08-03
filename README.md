# runtime-attestor

`runtime-attestor` produces signed, fail-closed runtime trust reports for SecAI_OS. It verifies model digests against the registry, container identity, listeners, mounts, GPU exposure, and policy-file hashes.

## Security model

- An enabled collector that is skipped, errors, or lacks an approved baseline makes the overall verdict `fail`.
- Reports use Ed25519. Verification requires an independently supplied trusted public key; an embedded key is never accepted as a trust anchor.
- The daemon refuses to start without an owner-only bearer token of at least 32 characters and a strict, bounded, valid audit chain. Audit write/sync loss makes `/health` return `503` and blocks protected operations.
- Configuration, keys, registry responses, command output, and HTTP headers/bodies are bounded. Unsafe files and cross-origin redirects are rejected.
- Registry connections require HTTPS except for loopback development endpoints.
- `/health` is intentionally unauthenticated and discloses only readiness. Every `/v1/*` endpoint requires authentication and endpoint-wide rate limiting.

The example policy is deliberately not a production trust baseline: populate exact container image references and approved policy hashes before relying on a passing verdict.

## Development

Go 1.25 or newer is required for descriptor-rooted checkpoint filesystem
operations; CI and production images use Go 1.26.5.

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...
```

Generate a signing keypair and run a one-shot attestation:

```sh
go run . keygen -priv attestor.key -pub attestor.pub
go run . attest -policy policies/default-policy.yaml -key attestor.key -output report.json
go run . verify -report report.json -pubkey attestor.pub
```

## Signed audit checkpoints and recovery

These checkpoint commands and their filesystem guarantees are Fedora/Linux
production features. They rely on POSIX UID ownership, no-follow opens, hard
links, and directory `fsync`; POSIX macOS is suitable for development testing,
but Windows filesystems are not supported by this recovery boundary.

The attestor can export its operational audit log as a provider-neutral,
owner-only JSON checkpoint. It embeds the complete audit bytes and signs their
SHA-256 digest, entry count, chain head, timestamp, and public-key identity with
Ed25519. Verification uses a separately supplied trusted public key and replays
the strict audit chain. Export and recovery write and sync a randomized
same-directory temporary file, publish it with an atomic no-replace hard link,
remove the temporary name, and sync the parent directory. Failed writes are
cleaned up before returning, so a partial final file cannot block a safe retry.

Provision a dedicated checkpoint keypair separately from the trust-report key,
keep the private key under independent restricted custody, and expose it only
for the stopped-writer procedure. Stop the daemon before exporting:

```sh
install -d -m 0700 /var/lib/secure-ai/checkpoints
runtime-attestor audit-checkpoint \
  -audit /var/lib/secure-ai/logs/attestor-audit.jsonl \
  -key /run/secure-ai/attestor-checkpoint.key \
  -output /var/lib/secure-ai/checkpoints/attestor-20260802.json

runtime-attestor audit-verify \
  -checkpoint /var/lib/secure-ai/checkpoints/attestor-20260802.json \
  -pubkey /etc/secure-ai/attestor-checkpoint.pub \
  -require-head PREVIOUSLY_RETAINED_CHAIN_HEAD
```

Run the exporter as the owner of both input and key. If custody uses a distinct
export identity, stop the daemon and stage an exact owner-only audit copy under
that identity first. Inputs and outputs must live in trusted
root/export-user-owned directories that are not group/world-writable; never
weaken the source or private-key mode.
All checkpoint source, key, checkpoint-output, and recovery-output paths must
be canonical absolute paths.

Copy each verified checkpoint to the chosen immutable retention system and
retain its reported head independently. Local `O_EXCL` creation is protection
against accidental replacement, not WORM storage, and `created_at` is not an
externally trusted timestamp.

Recovery requires that independent head to occur in the candidate chain and
only creates a new path:

```sh
runtime-attestor audit-recover \
  -checkpoint /recovery/attestor-20260802.json \
  -pubkey /etc/secure-ai/attestor-checkpoint.pub \
  -require-head INDEPENDENTLY_RETAINED_CHAIN_HEAD \
  -output /var/lib/secure-ai/logs/attestor-audit.recovered.jsonl
```

Start the daemon against the recovered path to run its normal verification
before promoting it operationally. Signed trust reports are separate evidence
and must be backed up with the checkpoint.

## Daemon deployment

Provide these owner-only files and writable storage as mounts:

- `SERVICE_TOKEN_PATH` (default `/run/secure-ai/service-token`, mode `0600`)
- the Ed25519 private key referenced by policy (mode `0600`)
- `/var/lib/secure-ai` for owner-only signed reports written to `attestation.report.output_dir` and the hash-chained audit log
- read-only access to every configured evidence source

Bind the API to loopback or an authenticated private service network. Run the container with a read-only root, all capabilities dropped, `no-new-privileges`, a PID limit, and explicit CPU/memory limits. Grant device or host-runtime access only when the selected collectors require it; never mount an unrestricted container-engine socket merely for convenience.

Daemon attestations persist their final signed report atomically. A persistence failure forces the latest verdict to `fail` and is audit-recorded; unsigned reports are never persisted. Stop the daemon before rotating the 64 MiB audit log, create and verify a final checkpoint, and preserve its chain head independently.

HTTP endpoints are `/health`, `/v1/attest`, `/v1/report/latest`, `/v1/reload`, and `/v1/metrics`.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the detailed review, validation record, and residual trust assumptions.
