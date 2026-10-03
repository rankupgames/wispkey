#!/usr/bin/env python3
"""Compare uploaded/downloaded artifact paths and bytes, not ZIP permissions."""

import argparse
import hashlib
from pathlib import Path


def inventory(root):
    root = Path(root)
    if not root.is_dir():
        raise ValueError("artifact directory is missing")
    result = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("artifact contains a symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise ValueError("artifact directory is empty")
    return result


def verify(source, downloaded):
    if inventory(source) != inventory(downloaded):
        raise ValueError("artifact paths or content changed during upload/download")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("downloaded", type=Path)
    args = parser.parse_args()
    try:
        verify(args.source, args.downloaded)
    except ValueError as error:
        parser.exit(1, f"Artifact verification failed: {error}\n")
    print("Artifact paths and content match")


if __name__ == "__main__":
    main()
