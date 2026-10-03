#!/usr/bin/env python3
"""Plan a per-user native-host registration. Write only with explicit --install."""
import argparse
import ctypes
import errno
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

# Darwin sys/acl.h. Permit only non-mutating allow rights; deny entries cannot
# grant access. Do not resolve principals or assume a preceding deny wins.
ACL_SAFE_ALLOW = sum(1 << bit for bit in (1, 3, 7, 9, 11, 20))
ACL_MAX_ENTRIES = 128


def acl_library():
    if sys.platform != "darwin":
        raise ValueError("Darwin ACL inspection is required")
    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        pointer = ctypes.c_void_p
        signatures = {
            "acl_get_fd_np": ([ctypes.c_int, ctypes.c_int], pointer),
            "acl_valid": ([pointer], ctypes.c_int),
            "acl_get_entry": ([pointer, ctypes.c_int, ctypes.POINTER(pointer)], ctypes.c_int),
            "acl_get_tag_type": ([pointer, ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
            "acl_get_permset_mask_np": ([pointer, ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int),
            "acl_free": ([pointer], ctypes.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(lib, name)
            function.argtypes, function.restype = arguments, result
        return lib
    except (OSError, AttributeError) as error:
        raise ValueError("Darwin ACL inspection is unavailable") from error


def validate_acl_entries(lib, acl):
    if lib.acl_valid(acl) != 0:
        raise ValueError("invalid ACL")
    for index in range(ACL_MAX_ENTRIES + 1):
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = lib.acl_get_entry(acl, index, ctypes.byref(entry))
        # Darwin uses -1/EINVAL for the end of a valid, indexed ACL.
        if result == -1 and ctypes.get_errno() == errno.EINVAL:
            return
        if result != 0 or not entry.value or index == ACL_MAX_ENTRIES:
            raise ValueError("unreadable or oversized ACL")
        tag, permissions = ctypes.c_int(), ctypes.c_uint64()
        if lib.acl_get_tag_type(entry, ctypes.byref(tag)) != 0 or lib.acl_get_permset_mask_np(entry, ctypes.byref(permissions)) != 0:
            raise ValueError("unreadable ACL entry")
        if tag.value not in (1, 2) or (tag.value == 1 and permissions.value & ~ACL_SAFE_ALLOW):
            # Includes inherited and inherit-only grants: they could compromise
            # newly created registration directories or the temporary manifest.
            raise ValueError("ACL permits mutation or has unsupported rights")


def validate_acl_fd(fd):
    lib = acl_library()
    ctypes.set_errno(0)
    acl = lib.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED
    if not acl:
        # Apple's acl_get_fd_np -> fstatx_np -> filesec_get_property returns
        # ENOENT for an absent ACL property. A descriptor avoids confusing this
        # with a missing pathname; every other error fails closed.
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ValueError("unable to inspect ACL")
    try:
        validate_acl_entries(lib, acl)
    finally:
        lib.acl_free(acl)


def validate_acl(path, info):
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(info):
            raise ValueError("path changed during validation")
        validate_acl_fd(fd)
        if identity(os.fstat(fd)) != identity(info) or identity(path.lstat()) != identity(info):
            raise ValueError("path changed during validation")
    finally:
        os.close(fd)


def validate_ancestors(path):
    # Validate from root down before inspecting children. Sticky shared parents
    # protect trusted-owner child entries, but never excuse a mutating ACL.
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
            raise ValueError("ancestors must be non-symlink directories owned by root or this user")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise ValueError("ancestors must not permit untrusted entry replacement")
        validate_acl(ancestor, info)


def validate_host(host_path):
    host = Path(host_path)
    if not host.is_absolute():
        raise ValueError("host path must be absolute")
    host = host.resolve(strict=True)
    validate_ancestors(host)
    info = host.lstat()
    if not stat.S_ISREG(info.st_mode) or not os.access(host, os.X_OK):
        raise ValueError("host must be an executable regular file")
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("host must be owned by this user and not writable by other users")
    validate_acl(host, info)
    return host


def plan(browser, extension_id, host_path, home):
    if browser not in LOCATIONS:
        raise ValueError("unsupported browser")
    host = validate_host(host_path)
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
    validate_registration_directories(destination, home, create=False)
    return destination, manifest


def validate_registration_directories(destination, home, *, create):
    home = Path(home)
    validate_ancestors(home.resolve(strict=True))
    relative = destination.relative_to(home)
    current = home
    # Refuse symlink/redirection and insecure existing directories. Never change
    # permissions on an existing directory or overwrite an existing registration.
    for part in (None, *relative.parts[:-1]):
        if part is not None:
            current = current / part
        if not current.exists() and not current.is_symlink():
            if not create:
                break
            current.mkdir(mode=0o700)
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("registration directories must be owner-controlled, non-symlink directories")
        validate_acl(current, info)


def install(destination, manifest, home):
    """No sudo, browser settings, extension installation or host execution."""
    # Revalidate the canonical path at publication; do not follow a new symlink
    # introduced after planning. No chmod, copying or repair of existing paths.
    if str(validate_host(manifest["path"])) != manifest["path"]:
        raise ValueError("host path changed after planning")
    validate_registration_directories(destination, home, create=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            validate_acl_fd(output.fileno())
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
        print("Registration refused: check OS, exact extension ID, absolute executable path, directory ownership, ACLs and existing manifest. No existing file was replaced.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
