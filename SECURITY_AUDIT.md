# Security and Production-Readiness Audit

Audit date: 2026-08-02

## Scope

The audit covered policy parsing, every collector, comparison and verdict semantics, report signing and verification, daemon authentication and HTTP behavior, audit persistence, filesystem and subprocess boundaries, container packaging, dependencies, tests, and GitHub automation. The review was source-based and exercised in Linux containers on a macOS development host; it was not a penetration test of a deployed Fedora GPU host.

## Remediated findings

- **Critical — unavailable evidence could still produce a usable attestation.** Every enabled collector now contributes to the score, and skipped, errored, unknown, missing-baseline, or empty-collector states fail closed.
- **Critical — signature trust was self-selected and signing failures could leave a positive report.** Verification now requires an independently supplied Ed25519 public key. The embedded key and signing timestamp are authenticated, a configured signing failure forces a zero-score `fail`, and an unsigned report can never pass.
- **Critical — daemon authentication could be absent.** Startup now requires a bounded, regular, owner-only token file; comparison is constant-time and every non-health endpoint is protected.
- **High — model, policy, and credential files were vulnerable to unsafe-file, race, and resource-exhaustion behavior.** Reads reject symlinks and non-regular files, verify file identity across open/read, enforce limits, reject unmeasured vault subdirectories, and cap entry counts. Generated private keys are owner-only and never overwrite an existing file.
- **High — registry responses and redirects were insufficiently constrained.** URLs, redirect origin/count, response size, schema, manifest size, filenames, duplicate entries, and SHA-256 digests are validated. Plain HTTP is limited to loopback.
- **High — allowlist violations were reported too weakly.** Unapproved models, containers, listeners, GPU devices, and changed policy hashes now carry hard-failure findings. Missing approved models and expected devices are detected.
- **High — local audit corruption or loss could be ignored.** The complete append-only SHA-256 audit chain is strictly decoded and verified before startup; unsafe paths, unknown/trailing JSON, weak permissions, oversized lines/logs, and broken timestamps/chains are rejected. Every append/sync is checked, failures poison readiness and protected routes, and a 64 MiB cap requires controlled rotation.
- **High — configured report persistence was not implemented.** Daemon attestations now persist final signed reports atomically as owner-only files in `report.output_dir`. Persistence failure forces and re-signs a zero-score fail report, prevents a positive latest result, and is audit-recorded.
- **High — audit rollback had no portable local anchor or guarded recovery path.** The CLI now exports the complete operational audit chain in an owner-only Ed25519-signed checkpoint whose payload digest, entry count, head, embedded key identity, and chain are independently verified. Export never overwrites, and recovery requires a separately retained head, verifies that the candidate contains it, and writes only to a new fsynced path.
- **Medium — subprocess and HTTP denial-of-service paths were unbounded.** Collector commands have deadlines and output caps; the daemon has bounded headers and server timeouts, serialized attestations, rate limiting, and graceful shutdown.
- **Supply chain / operations.** The image uses digest-pinned Go 1.26.5 and Alpine 3.23 bases, a stripped static binary, a non-root UID, a health check, a narrow build context, and durable state volumes. The runtime copies CA roots from the immutable builder stage instead of installing unpinned packages. CI actions are SHA-pinned and enforce module verification, formatting, bounded race tests, vet, `govulncheck`, current-tree and full-history secret scanning, container builds, CodeQL, and Dependabot updates. Tagged releases produce Linux binaries, a CycloneDX SBOM, Sigstore-signed checksums, and GitHub provenance attestations. A read-only release gate requires a v-prefixed strict SemVer annotated tag that resolves exactly to the workflow commit and is contained in `origin/main`; write and OIDC permissions remain confined to the publishing job.

## Residual risks and deployment requirements

- Reports are software measurements, not TPM/TEE-backed remote attestation. They have no verifier nonce, transparency-log inclusion, or trusted external timestamp, so replay prevention and hardware identity must be supplied by the control plane.
- The checkpoint format is a local provider-neutral handoff, not WORM storage or a trusted timestamp. A privileged actor able to replace evidence, signing keys, and independently retained heads remains outside the local boundary. The deployment must choose hardware-backed or tightly restricted key custody, immutable/object-lock storage, retention duration, replication, encryption, checkpoint cadence, and head distribution.
- Checkpoint filesystem hardening is supported for the Fedora/Linux production target and depends on POSIX UID, no-follow, hard-link, and directory-sync semantics; it is not a Windows recovery implementation.
- Container image observation is based on the runtime's reported image reference, not a measured running root filesystem. Provision digest references and combine this service with signed-image admission and runtime policy.
- Collector accuracy is limited to the daemon's namespaces and granted devices/files. Do not claim host-wide trust from a container that cannot see the host evidence; unavailable evidence now fails closed.
- The bearer token is a single service credential, not mTLS or role-based authorization. Rotate it externally, restrict the listener, and use a private authenticated network.
- Fedora, SELinux, Podman, NVIDIA/AMD devices, and real host namespace behavior still require hardware-in-the-loop integration and failure-injection testing before a production trust claim.

## Verification performed

- 60 top-level tests via `go test -race -count=1 ./...`, including checkpoint tamper, trust-anchor, canonical-path, decoded-size, unsafe-mode/directory, injected partial-write cleanup/retry, rollback-anchor, no-overwrite, and exact-byte recovery cases
- `go vet ./...`
- `govulncheck ./...` with `golang.org/x/vuln/cmd/govulncheck@v1.3.0` — no reachable vulnerabilities
- `gosec@v2.28.0 -severity medium -confidence medium ./...` — no findings
- Gitleaks 8.30.1 current tree and Git history — no leaks
- Trivy 0.70.0 filesystem, Dockerfile, and image scan at HIGH/CRITICAL — no findings (database dated 2026-08-02)
- Digest-pinned Docker image build and inspection — non-root UID `65534:65534`
- Actionlint on all workflows — no findings
- Release dependency/permission graph checks, strict SemVer positive/negative fixtures, and synthetic annotated/lightweight/off-main Git ancestry cases — passed
