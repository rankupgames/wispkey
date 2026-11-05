#!/usr/bin/env bash
# Package a WispKey release archive with the binary, license, README, and version metadata.
# Requires Bash and Python 3; PYTHON can select the Python interpreter.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: package-release-asset.sh --target TRIPLE --binary PATH --version VERSION \
  --commit SHA --license PATH --readme PATH --out-dir DIR
EOF
  exit 2
}

target=""
binary=""
version=""
commit=""
license=""
readme=""
out_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --binary) binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --commit) commit="${2:-}"; shift 2 ;;
    --license) license="${2:-}"; shift 2 ;;
    --readme) readme="${2:-}"; shift 2 ;;
    --out-dir) out_dir="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ -z "$target" || -z "$binary" || -z "$version" || -z "$commit" || -z "$license" || -z "$readme" || -z "$out_dir" ]]; then
  echo "missing required argument" >&2
  usage
fi

if [[ ! -f "$binary" ]]; then
  echo "binary not found: $binary" >&2
  exit 1
fi
if [[ ! -f "$license" ]]; then
  echo "license not found: $license" >&2
  exit 1
fi
if [[ ! -f "$readme" ]]; then
  echo "readme not found: $readme" >&2
  exit 1
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-].*)?$ ]]; then
  echo "invalid version: $version" >&2
  exit 1
fi
if [[ ! "$commit" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "commit must be a 40-character SHA: $commit" >&2
  exit 1
fi

binary_name="$(basename "$binary")"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

cp "$binary" "$stage/$binary_name"
if [[ "$binary_name" != *.exe ]]; then
  chmod +x "$stage/$binary_name"
fi
cp "$license" "$stage/LICENSE"
cp "$readme" "$stage/README.md"
cat > "$stage/VERSION" <<EOF
name: wispkey
version: ${version}
commit: ${commit}
license: Apache-2.0
homepage: https://github.com/rankupgames/wispkey
EOF

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

if [[ "$binary_name" == *.exe ]]; then
  archive="wispkey-${target}.zip"
  (
    cd "$stage"
    # tar -a may create a tar container despite the .zip suffix (GNU tar).
    "${PYTHON:-python3}" -m zipfile --create "$out_dir/$archive" "$binary_name" LICENSE README.md VERSION
  )
else
  archive="wispkey-${target}.tar.gz"
  (
    cd "$stage"
    # Set the executable mode in the archive, including on Windows filesystems.
    "${PYTHON:-python3}" - "$out_dir/$archive" "$binary_name" <<'PY'
import sys
import tarfile

with tarfile.open(sys.argv[1], "w:gz") as archive:
    for name in [sys.argv[2], "LICENSE", "README.md", "VERSION"]:
        entry = archive.gettarinfo(name)
        if name == sys.argv[2]:
            entry.mode |= 0o111
        with open(name, "rb") as payload:
            archive.addfile(entry, payload)
PY
  )
fi

test -s "$out_dir/$archive"
echo "$out_dir/$archive"
