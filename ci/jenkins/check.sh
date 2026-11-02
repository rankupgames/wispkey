#!/usr/bin/env bash
# Run one Linux lane of the committed CI gates, in order. Do not install or replace worker tools.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
lane="${1:?usage: check.sh rust|tray|browser|postgres|cross-node}"
lane_root="$PWD/target/jenkins"

need_rust() {
    export PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=stable RUSTC_WRAPPER='' CARGO_TERM_COLOR=never
    test "$(rustc --version | cut -d' ' -f1-2)" = 'rustc 1.99.0'
    test "$(cargo --version | cut -d' ' -f1-2)" = 'cargo 1.99.0'
    test -f Cargo.lock
}

need_node() {
    test "$(node --version)" = 'v24.21.0'
    test "$(npm --version)" = '11.19.0'
    test "$(npm config get min-release-age)" = '7'
    test -f browser-extension/package-lock.json
    test -f crates/wispkey-tray/ui/package-lock.json
}

build_tray_ui() {
    (cd crates/wispkey-tray/ui && npm ci && npm run build)
}

case "$lane" in
rust)
    need_rust
    test "$(python3 --version)" = 'Python 3.12.3'
    command -v strace >/dev/null || { echo 'strace is required' >&2; exit 1; }
    cargo fmt --check
    cargo install cargo-audit --version 0.22.2 --locked --root "$lane_root/tools"
    PATH="$lane_root/tools/bin:$PATH" cargo audit
    cargo clippy --locked --all-targets --features experimental-browser-receiver -- -D warnings \
        -W clippy::suspicious -W clippy::style -W clippy::perf -W clippy::complexity
    cargo clippy --locked --all-targets --features vsock,experimental-sync,experimental-browser-receiver -- -D warnings
    cargo test --locked --lib schema
    cargo test --locked --features experimental-browser-receiver
    cargo test --locked --features vsock,experimental-sync,experimental-browser-receiver
    python3 scripts/verify_personal_offline.py
    cargo publish --dry-run --locked
    cargo build --locked --release
    ;;
tray)
    need_rust
    need_node
    pkg-config --exists gtk+-3.0 webkit2gtk-4.1 ayatana-appindicator3-0.1 \
        || { echo 'GTK, WebKitGTK and AppIndicator development packages are required' >&2; exit 1; }
    test -f /usr/include/xdo.h || { echo 'libxdo development package is required' >&2; exit 1; }
    build_tray_ui
    cargo build --locked -p wispkey-tray
    cargo test --locked -p wispkey-tray
    ;;
postgres)
    # The registry declares this exact name as the lane's only owned container.
    need_rust
    export CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0
    WISPKEY_CONTAINER_ENGINE=docker WISPKEY_FIXTURE_CONTAINER_NAME=wispkey-postgres-fixture \
        bash tests/support/postgres_operation_fixture.sh
    ;;
cross-node)
    # The registry declares wk-ssh-jenkins and wk-accept-jenkins-control-plane as owned containers.
    need_rust
    for tool in docker ssh ssh-keygen curl sha256sum; do
        command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
    done
    mkdir -p "$lane_root/tools/kind"
    curl --fail --location --silent --show-error --output "$lane_root/tools/kind/kind" \
        https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64
    echo 'aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d  kind' > "$lane_root/tools/kind/kind.sha256"
    (cd "$lane_root/tools/kind" && sha256sum --check --quiet kind.sha256)
    chmod 700 "$lane_root/tools/kind/kind"
    KIND="$lane_root/tools/kind/kind" CARGO_BUILD_JOBS=2 WISPKEY_CROSS_NODE_SUFFIX=jenkins \
        python3 scripts/verify.py --suite cross-node
    ;;
browser)
    need_node
    test "$(python3 --version)" = 'Python 3.12.3'
    export PLAYWRIGHT_BROWSERS_PATH="$lane_root/ms-playwright"
    (cd browser-extension && npm ci && npm test && npm run build)
    build_tray_ui
    (cd browser-extension && npx playwright install chromium firefox && npm run test:browser)
    python3 -m unittest discover -s scripts/tests -v
    # Pack the extensions as the lane artifact, unpack them as a consumer, and require identical trees.
    artifact="$lane_root/artifacts"
    rm -rf -- "$artifact"
    mkdir -p "$artifact/downloaded"
    tar --create --file "$artifact/wispkey-browser-extensions.tar" -C browser-extension/dist .
    tar --extract --file "$artifact/wispkey-browser-extensions.tar" -C "$artifact/downloaded"
    python3 scripts/verify_artifact_tree.py browser-extension/dist/ "$artifact/downloaded"
    ;;
*)
    echo "unknown lane: $lane" >&2
    exit 2
    ;;
esac
