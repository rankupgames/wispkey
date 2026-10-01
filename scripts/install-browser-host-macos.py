#!/usr/bin/env python3
"""Plan a per-user native-host registration. Write only with explicit --install."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

NAME = "com.wispkey.browser"
FIREFOX_ID = "browser-handoff@wispkey.local"
LOCATIONS = {
    "Chrome": "Library/Application Support/Google/Chrome/NativeMessagingHosts",
    "Edge": "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    "Firefox": "Library/Application Support/Mozilla/NativeMessagingHosts",
}


def plan(browser, extension_id, host_path, home):
    if browser not in LOCATIONS:
        raise ValueError("unsupported browser")
    host = Path(host_path)
    if not host.is_absolute():
        raise ValueError("host path must be absolute")
    host = host.resolve(strict=True)
    info = host.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(host, os.X_OK):
        raise ValueError("host must be an executable regular file")
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("host must be owned by this user and not writable by other users")
    manifest = {"name": NAME, "description": "WispKey local browser approval host", "path": str(host), "type": "stdio"}
    if browser == "Firefox":
        if extension_id not in (None, FIREFOX_ID):
            raise ValueError("use the Firefox ID from the WispKey extension manifest")
        manifest["allowed_extensions"] = [FIREFOX_ID]
    else:
        if not extension_id or not re.fullmatch(r"[a-p]{32}", extension_id):
            raise ValueError("supply the exact 32-character extension ID from this browser")
        manifest["allowed_origins"] = [f"chrome-extension://{extension_id}/"]
    home = Path(home)
    if not home.is_absolute():
        raise ValueError("home must be absolute")
    destination = home / LOCATIONS[browser] / f"{NAME}.json"
    return destination, manifest


def install(destination, manifest, home):
    """No sudo, browser settings, extension installation or host execution."""
    home = Path(home)
    relative = destination.relative_to(home)
    current = home
    # Refuse symlink/redirection and insecure existing directories. Never change
    # permissions on an existing directory or overwrite an existing registration.
    for part in (None, *relative.parts[:-1]):
        if part is not None:
            current = current / part
        if not current.exists() and not current.is_symlink():
            current.mkdir(mode=0o700)
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("registration directories must be owner-controlled, non-symlink directories")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            json.dump(manifest, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        # Hard-link publishes a complete file atomically and refuses an existing
        # destination (including a symlink), unlike a replacing rename.
        os.link(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=LOCATIONS, required=True)
    parser.add_argument("--extension-id")
    parser.add_argument("--host-path", type=Path, required=True)
    parser.add_argument("--install", action="store_true", help="explicitly write the displayed per-user registration; default is a read-only plan")
    args = parser.parse_args(argv)
    try:
        if sys.platform != "darwin":
            raise ValueError("this installer supports macOS only")
        if os.geteuid() == 0:
            raise ValueError("run as your normal user, never with sudo")
        destination, manifest = plan(args.browser, args.extension_id, args.host_path, Path.home())
        if args.install:
            install(destination, manifest, Path.home())
        print(json.dumps({"status": "installed" if args.install else "planned", "destination": str(destination), "manifest": manifest}, indent=2))
        return 0
    except (OSError, ValueError):
        print("Registration refused: check OS, exact extension ID, absolute executable path, directory ownership and existing manifest. No existing file was replaced.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
