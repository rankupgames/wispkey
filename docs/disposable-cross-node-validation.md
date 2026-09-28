# Disposable SSH and Kubernetes acceptance

Run on Linux or inside WSL, with Docker, Rust, Python 3.10+, `ssh-keygen`, and
kind 0.33+ available. The host-built helper must run in Ubuntu 24.04; the CI job
uses that same Ubuntu release to keep its libc compatible with the container.
This fixture creates its own targets; it needs no existing
cluster, vault, SSH account, or cloud/provider credentials.

```sh
python3 scripts/verify.py --suite cross-node
# If kind is installed outside PATH:
KIND=/private/tools/kind python3 scripts/verify.py --suite cross-node
```

The GitHub workflow **Disposable cross-node acceptance** runs the same fixture
for operation changes and supports manual dispatch. It installs a checksum-pinned
kind release. The Ubuntu container base is pinned by digest. kind selects its
release's default node image. Package installation needs internet access.

The fixture uses unique resource names and private temporary files. SSH and the
Kubernetes API bind to loopback. A dedicated kubeconfig prevents changes to the
normal kubectl context. Cleanup removes only the resources created by this run,
including on test failure. It never stops an existing container or cluster.

## What is verified

- A real OpenSSH daemon admits a dedicated key-only account whose authorized key
  forces the restricted WispKey helper. Forwarding, terminals, password login and
  root SSH login are disabled. The root-owned helper configuration permits one
  fixed program. A private SQLite database records attempts durably.
- The transport rejects a wrong host-key pin before releasing the synthetic
  credential. A correct request executes the fixed destination program once;
  replay of that attempt is rejected before a second release. The destination
  records only an `accepted` marker, and container logs are checked for the
  synthetic credential canary.
- A real kind API uses a private CA and a short-lived service-account token.
  RBAC permits reading one named namespace and reading/updating one pre-created
  Secret. The fixture verifies that listing, creating and deleting Secrets, and
  creating workloads, are denied.
- The API server starts with an AES-CBC Secret encryption configuration. Before
  issuing the signed fixture posture, the harness reads the selected object's
  raw etcd record and verifies its encrypted storage prefix. This follows the
  [Kubernetes encryption-at-rest verification procedure](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/).
  The configuration hash binds the fixture posture to that setup.
- A signed but incorrect namespace UID prevents selected-secret release. Correct
  delivery preserves the existing Secret UID, other data and annotations. A
  repeated credential revision leaves `resourceVersion` unchanged. Revocation
  removes only the selected data key and reports `RevocationUnverified`, since
  deleting a Kubernetes value cannot prove a consumer forgot it.

The two ignored Rust tests are invoked by this harness; run the harness instead
of invoking them without its private metadata. Their credentials and signing
keys are disposable. Assertions do not print plaintext credential values.

## Scope of the evidence

The first real OpenSSH run exposed a client rejection of the normal
`WindowAdjusted` message before helper readiness. The transport now accepts that
flow-control event while still requiring the authenticated ready message before
secret release. The ordinary SSH fixture uses a small receive window to cover
this behavior without Docker as well.

These tests validate actual SSH/Kubernetes transport and destination behavior.
The separate runtime tests in PR #35 cover owner-issued one-use grants, expiry,
scope, concurrency, cancellation and reconciliation. The harness calls the
transport adapters directly; it does not claim a real human approved a grant or
that an external production environment has the fixture's configuration.

Deployment-specific acceptance still needs that deployment's reviewed identity,
posture, helper installation and intended application behavior. Windows Hello
browser approval/cancellation remains human acceptance in
[browser-handoff.md](browser-handoff.md).
