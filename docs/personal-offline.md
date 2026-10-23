# Personal accountless and offline proof

Personal local operations do not require a Cloud account or Cloud session.
Vault startup, credential storage, project/partition selection, token rotation,
lock/unlock, local audit export and deletion remain local. The HTTP proxy can
substitute tokens for a reachable local service without external connectivity.
An offline proxy cannot reach a remote upstream. Cloud login and sync are
explicit network operations and are outside this guarantee.

## Repeat the proof

Run from this repository on Linux or WSL with Python 3.10+, Rust, `ip`, `unshare`
and `strace`. Install these development tools before denying the network.
Cargo builds the locked smoke, proxy, audit and MCP test binaries before the
network namespace starts. Dependency acquisition is not part of the runtime
proof. No real vault, password, account or provider key is needed.

```sh
python3 scripts/verify.py --suite offline
# Hosts that disallow unprivileged user namespaces, including CI:
python3 scripts/verify_personal_offline.py --sudo
```

The default command creates a new user and network namespace. `--sudo` uses
noninteractive sudo only for the isolated worker; Cargo still builds as the
caller. The worker requires exactly one loopback interface and no IPv4 routes,
brings loopback up and verifies that a connection to a reserved external test
address fails with `ENETUNREACH`.

The test processes receive only tool paths and a disposable home/vault location.
They receive no inherited account, Cloud, sideload or password configuration.
Each fixture supplies its own synthetic credentials. `strace` follows child
processes and checks decoded socket connection/bind destinations and datagram
send calls. External, Unix-mediated and undecodable attempts fail the proof,
even if the operating system rejected them. Connected TCP writes contain no
caller-selected destination; their connections are checked separately. Kernel
netlink queries are allowed. Trace buffers are suppressed so sent credentials
cannot enter the trace. Raw traces and fixture output stay in temporary storage
and are removed on success or failure.

The CLI lifecycle fixture creates a vault, project and partition, stores a
synthetic value through stdin, lists metadata, obtains and rotates an opaque
token, locks the vault, verifies locked access fails, unlocks from a fresh CLI
process, reads the preserved token, exports audit metadata and deletes the
credential. It checks stdout, stderr and regular vault files for the plaintext
canary and its base64 encoding, and verifies no Cloud configuration was created.
Existing proxy, audit and MCP fixtures exercise local substitution and protocol
boundaries in the same denied-network namespace.

## Evidence and release acceptance

The runner emits one redacted JSON result only after all four suites pass and
at least one traced loopback connection is observed. Record the tested commit,
OS/tool versions, tester/date and this JSON in the release acceptance record.
No trace, vault contents, fixture output or credential value belongs in that
record. A failed or interrupted run does not count as acceptance.

The DEV-3 WSL Ubuntu run on 2026-10-09 passed all four suites with nine loopback
connections and zero non-loopback attempts. The lifecycle fixture also passed
on Windows. The trace acceptance/rejection tests passed in the Python automation
suite. The Linux CI job repeats the proof for every change.

This is the accountless runtime evidence for **Personal / Local GA**, and the
local-independence gate for **Cloud MVP**. It does not prove Cloud ciphertext
storage, account isolation, production authentication or deployment behavior;
those need the separate Cloud acceptance record. It also does not certify
native Windows Hello/Touch ID approval, IDE installation or every local command.
The fixtures use the file protector and synthetic credentials. The fresh-process
check is session recovery, not a power-loss or hardware recovery test. Explicit
owner plaintext egress through `exec`, `run`, `inject` and browser approval has
its own documented boundary.

The release maintainer owns reruns. Repeat before Personal or Cloud release
acceptance, and after changes to startup, storage/session protection, credential
commands, proxy/MCP, audit, Cloud defaults, dependencies or the proof runner.
Use the same synthetic procedure on each supported release platform; native
platform acceptance complements the Linux denied-network result.

## Troubleshooting

A missing `strace`, `ip` or `unshare`, denied namespace permission, build failure,
undecodable trace, fixture failure or absent loopback positive control returns
nonzero. Install the missing development tool or enable the host's namespace
support; use `--sudo` only where noninteractive sudo is already authorized.
Do not remove tracing or run on the host network to turn a failure into a pass.
Review failing fixtures with disposable synthetic state; do not upload raw
output. Windows users run the network proof inside configured WSL, with Linux
Rust/tool paths and a Linux build target directory.
