# Debian 12 CLI and helper test artifacts

The `Compatible CLI and helper test artifacts` workflow builds both `wispkey`
and `wispkey-operation-helper` for `x86_64-unknown-linux-gnu` using Rust 1.94.0
in a pinned Debian 12 build image. It uses the committed lockfile, two build
workers, no incremental compilation, and a 6 GiB build-container memory limit.
The build job has a 40-minute limit and validation has 15 minutes.

The workflow records the exact checked source commit, immutable amd64 build and
runtime image digests, compiler, package inventory, binary hashes, ELF dependency
names, and required GLIBC symbol versions. It rejects requirements newer than
2.36, unexpected interpreters/architecture, and embedded library search paths.
Image pins were resolved from the official `library/rust:1.94.0-bookworm` and
`library/debian:bookworm-slim` manifests. Apt prerequisites are installed only in
disposable build/runtime containers and their resolved versions are recorded.

Validation downloads the supplied artifacts into a separate runner. A clean
runtime image contains no compiler or mounted build tree. It checks dynamic
dependency resolution and CLI version/help, then starts a loopback-only OpenSSH
container with a fresh synthetic key, forced restricted helper, fixed action and
private replay store. Wrong pins/keys cannot reach readiness. A successful
delivery executes the action once; replay, cancellation and expiry do not deliver
again. Raw/base64 canaries are checked across captured output and container logs.
The helper is never run against the runner's `/etc/wispkey` or helper state.

Only `verified-bookworm-cli-helper-<full SHA>` is an accepted test artifact.
`unvalidated-bookworm-cli-helper` is a one-day intermediate transfer, not evidence
of compatibility. Verified artifacts retain both binaries, SHA256SUMS and build/
runtime reports for seven days. Push/manual runs add GitHub artifact provenance;
PR runs are test candidates without that attestation. No tags, release pages,
package publication, installed CLI replacement or live-host access occurs.

This is an amd64 userspace compatibility slice, not proof about any particular
machine. Confirm target architecture, kernel, trust roots and operator setup
separately. The artifact fixture uses system OpenSSH as its protocol client;
production Rust HTTP-to-SSH and Kubernetes/Postgres tests remain separate suites.
It does not test a Cloud-connected browser login, OS approval, actual provider
authentication or production destination installation.
