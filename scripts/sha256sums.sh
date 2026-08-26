#!/usr/bin/env bash
# Write a GNU coreutils-compatible SHA256SUMS file for every regular file in a directory.
set -euo pipefail

usage() {
  echo "Usage: sha256sums.sh --dir DIR --out PATH" >&2
  exit 2
}

dir=""
out=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) dir="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ -z "$dir" || -z "$out" ]]; then
  usage
fi
if [[ ! -d "$dir" ]]; then
  echo "directory not found: $dir" >&2
  exit 1
fi

dir="$(cd "$dir" && pwd)"
out_dir="$(dirname "$out")"
mkdir -p "$out_dir"
out="$(cd "$out_dir" && pwd)/$(basename "$out")"

shopt -s nullglob
files=()
while IFS= read -r path; do
  files+=("$path")
done < <(find "$dir" -maxdepth 1 -type f ! -name "$(basename "$out")" | LC_ALL=C sort)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "no files to checksum in $dir" >&2
  exit 1
fi

: > "$out"
for path in "${files[@]}"; do
  name="$(basename "$path")"
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum -- "$path" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 -- "$path" | awk '{print $1}')"
  fi
  if [[ ! "$digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "failed to hash $path" >&2
    exit 1
  fi
  printf '%s  %s\n' "$digest" "$name" >> "$out"
done

test -s "$out"
echo "$out"
