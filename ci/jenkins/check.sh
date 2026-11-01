#!/usr/bin/env bash
# Run one Linux lane of the committed CI gates, in order. Do not install or replace worker tools.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
lane="${1:?usage: check.sh rust|tray|browser}"
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
    WISPKEY_CONTAINER_ENGINE=podman bash tests/support/postgres_operation_fixture.sh
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
browser)
    need_node
    test "$(python3 --version)" = 'Python 3.12.3'
    export PLAYWRIGHT_BROWSERS_PATH="$lane_root/ms-playwright"
    (cd browser-extension && npm ci && npm test && npm run build)
    build_tray_ui
    (cd browser-extension && npx playwright install chromium firefox && npm run test:browser)
    python3 -m unittest discover -s scripts/tests -v
    ;;
*)
    echo "unknown lane: $lane" >&2
    exit 2
    ;;
esac
