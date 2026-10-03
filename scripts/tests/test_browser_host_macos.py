import importlib.util
import contextlib
import ctypes
import errno
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("installer", Path(__file__).parents[1] / "install-browser-host-macos.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@unittest.skipUnless(os.name == "posix", "macOS per-user filesystem contract")
class NativeHostInstallerTests(unittest.TestCase):
    def setUp(self):
        if sys.platform != "darwin":
            # POSIX filesystem tests are portable; only Darwin jobs exercise
            # the actual OS ACL reader. Production has no non-Darwin bypass.
            acl_reader = patch.object(installer, "validate_acl_fd")
            acl_reader.start()
            self.addCleanup(acl_reader.stop)
        self.scratch = tempfile.TemporaryDirectory(prefix="wispkey installer ")
        self.addCleanup(self.scratch.cleanup)
        self.home = Path(self.scratch.name)
        self.host = self.home / "host with spaces"
        self.host.write_text("synthetic executable fixture; never executed")
        self.host.chmod(0o700)

    def plan(self, browser="Chrome", extension_id="a" * 32, host=None):
        return installer.plan(browser, extension_id, host or self.host, self.home)

    def test_exact_manifest_for_each_browser_and_read_only_plan(self):
        for browser in ("Chrome", "Edge", "Firefox"):
            destination, manifest = self.plan(browser, None if browser == "Firefox" else "a" * 32)
            self.assertFalse(destination.parent.exists())
            self.assertEqual(destination.name, "com.wispkey.browser.json")
            self.assertEqual(manifest["path"], str(self.host.resolve()))
            self.assertEqual(manifest["type"], "stdio")
            self.assertEqual(manifest["name"], "com.wispkey.browser")
            if browser == "Firefox":
                self.assertEqual(manifest["allowed_extensions"], [installer.FIREFOX_ID])
                self.assertNotIn("allowed_origins", manifest)
            else:
                self.assertEqual(manifest["allowed_origins"], ["chrome-extension://" + "a" * 32 + "/"])
                self.assertNotIn("allowed_extensions", manifest)
            installer.install(destination, manifest, self.home)
            self.assertEqual(json.loads(destination.read_text()), manifest)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_malformed_or_broad_extension_ids_refused(self):
        for value in (None, "", "*", "A" * 32, "q" * 32, "a" * 31, "a" * 32 + "\n", "chrome-extension://" + "a" * 32 + "/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(extension_id=value)
        with self.assertRaises(ValueError):
            self.plan("Firefox", "other@example.com")
        with self.assertRaises(ValueError):
            self.plan("Safari")

    def test_invalid_host_paths_refused(self):
        for path in (Path("relative"), self.home, self.home / "missing"):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                self.plan(host=path)
        for mode in (0o600, 0o777):
            self.host.chmod(mode)
            with self.assertRaises(ValueError):
                self.plan()

    def test_existing_file_and_symlinks_never_overwritten(self):
        destination, manifest = self.plan()
        installer.install(destination, manifest, self.home)
        destination.write_text("existing registration")
        with self.assertRaises(FileExistsError):
            installer.install(destination, manifest, self.home)
        self.assertEqual(destination.read_text(), "existing registration")
        destination.unlink()
        destination.symlink_to(self.host)
        with self.assertRaises(FileExistsError):
            installer.install(destination, manifest, self.home)
        self.assertEqual(self.host.read_text(), "synthetic executable fixture; never executed")
        self.assertEqual(sorted(p.name for p in destination.parent.iterdir()), [destination.name])

    def test_secure_host_in_writable_parent_or_ancestor_is_refused(self):
        ancestor = self.home / "shared"
        parent = ancestor / "bin"
        parent.mkdir(parents=True, mode=0o700)
        host = parent / "host"
        host.write_text("synthetic")
        host.chmod(0o700)
        for directory, mode in [(parent, 0o777), (ancestor, 0o770)]:
            with self.subTest(directory=directory):
                directory.chmod(mode)
                with self.assertRaises(ValueError):
                    self.plan(host=host)
                directory.chmod(0o700)
        self.assertEqual(self.plan(host=host)[1]["path"], str(host.resolve()))

    def test_untrusted_ancestor_owner_is_refused_even_when_not_writable(self):
        original = installer.Path.lstat
        canonical_home = self.home.resolve()
        def lstat(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == canonical_home:
                fields = list(result)
                fields[4] = os.getuid() + 10000
                return os.stat_result(fields)
            return result
        with patch.object(installer.Path, "lstat", lstat), self.assertRaises(ValueError):
            self.plan()

    def test_input_symlink_is_canonicalized_and_cannot_redirect_manifest(self):
        alias = self.home / "host-alias"
        alias.symlink_to(self.host)
        destination, manifest = self.plan(host=alias)
        self.assertEqual(manifest["path"], str(self.host.resolve()))
        alias.unlink()
        alias.symlink_to(self.home / "different-host")
        installer.install(destination, manifest, self.home)
        self.assertEqual(json.loads(destination.read_text())["path"], str(self.host.resolve()))

    def test_parent_permissions_or_symlink_substitution_after_plan_is_refused(self):
        parent = self.home / "bin"
        parent.mkdir(mode=0o700)
        host = parent / "host"
        host.write_text("synthetic")
        host.chmod(0o700)
        destination, manifest = self.plan(host=host)
        parent.chmod(0o777)
        with self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)
        parent.chmod(0o700)
        moved = self.home / "moved"
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)
        self.assertFalse(destination.exists())

    def test_redirected_or_shared_parent_refused(self):
        destination, manifest = self.plan()
        other = self.home / "other"
        other.mkdir()
        (self.home / "Library").symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)

        self.assertFalse(list(other.iterdir()))
        (self.home / "Library").unlink()
        (self.home / "Library").mkdir(mode=0o777)
        (self.home / "Library").chmod(0o777)
        with self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)

    def test_cli_defaults_to_plan_and_requires_explicit_install(self):
        arguments = ["--browser", "Firefox", "--host-path", str(self.host)]
        destination, _ = self.plan("Firefox", None)
        with patch.object(installer.sys, "platform", "darwin"), patch.object(installer.os, "geteuid", return_value=1000), patch.object(installer.Path, "home", return_value=self.home):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(installer.main(arguments), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "planned")
            self.assertFalse(destination.parent.exists())
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(installer.main([*arguments, "--install"]), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "installed")
            self.assertTrue(destination.is_file())

    def test_cli_refuses_root_and_unsupported_platform_before_writing(self):
        for platform, uid in [("linux", 1000), ("darwin", 0)]:
            with patch.object(installer.sys, "platform", platform), patch.object(installer.os, "geteuid", return_value=uid), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(installer.main(["--browser", "Firefox", "--host-path", str(self.host), "--install"]), 1)
        self.assertFalse((self.home / "Library").exists())

    def test_acl_grants_on_host_ancestor_and_registration_refuse_read_only_plan(self):
        library = self.home / "Library"
        library.mkdir(mode=0o700)
        for target in (self.host, self.home, library):
            with self.subTest(target=target.name):
                def check(path, info):
                    if path.resolve() == target.resolve():
                        raise ValueError("synthetic mutation grant")
                with patch.object(installer, "validate_acl", side_effect=check), self.assertRaises(ValueError):
                    self.plan()
                self.assertEqual(list(library.iterdir()), [])

    def test_new_directory_and_inherited_manifest_acl_refused_without_publication(self):
        destination, manifest = self.plan()
        def check_directory(path, info):
            if path == self.home / "Library":
                raise ValueError("synthetic inherited directory grant")
        with patch.object(installer, "validate_acl", side_effect=check_directory), self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)
        self.assertFalse(destination.exists())
        self.assertEqual(list((self.home / "Library").iterdir()), [])
        # Directory preflight is controlled separately to inject an inherited
        # file ACL at the real temporary-file boundary, before JSON publication.
        with patch.object(installer, "validate_acl"), patch.object(installer, "validate_acl_fd", side_effect=ValueError("synthetic inherited file grant")), self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)
        self.assertFalse(destination.exists())
        self.assertEqual(list(destination.parent.iterdir()), [])

    def test_acl_changed_after_plan_is_refused(self):
        destination, manifest = self.plan()
        with patch.object(installer, "validate_acl_fd", side_effect=ValueError("changed ACL")), self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)
        self.assertFalse((self.home / "Library").exists())

    def test_acl_path_identity_change_and_symlink_refused(self):
        info = self.host.lstat()
        moved = self.home / "moved"
        self.host.rename(moved)
        self.host.write_text("replacement")
        with self.assertRaises(ValueError):
            installer.validate_acl(self.host, info)
        self.host.unlink()
        self.host.symlink_to(moved)
        with self.assertRaises(OSError):
            installer.validate_acl(self.host, info)

    def test_path_replaced_during_acl_read_and_missing_path_refused(self):
        info = self.host.lstat()
        def replace(fd):
            self.host.rename(self.home / "moved")
            self.host.write_text("replacement")
        with patch.object(installer, "validate_acl_fd", side_effect=replace), self.assertRaises(ValueError):
            installer.validate_acl(self.host, info)
        self.host.unlink()
        with self.assertRaises(FileNotFoundError):
            installer.validate_acl(self.host, info)


class AclReaderTests(unittest.TestCase):
    def library(self, entries=()):
        lib = Mock()
        lib.acl_valid.return_value = 0
        lib.acl_get_fd_np.return_value = 123
        def get_entry(acl, index, output):
            if index >= len(entries):
                ctypes.set_errno(errno.EINVAL)
                return -1
            output._obj.value = index + 1
            return 0
        def get_tag(entry, output):
            output._obj.value = entries[entry.value - 1][0]
            return 0
        def get_permissions(entry, output):
            output._obj.value = entries[entry.value - 1][1]
            return 0
        lib.acl_get_entry.side_effect = get_entry
        lib.acl_get_tag_type.side_effect = get_tag
        lib.acl_get_permset_mask_np.side_effect = get_permissions
        return lib

    def test_absent_acl_only_accepts_descriptor_enoent(self):
        for error in (errno.ENOENT, errno.EACCES, errno.EIO, errno.ENOTSUP, errno.EBADF, 0):
            lib = self.library()
            def absent(fd, kind):
                ctypes.set_errno(error)
                return None
            lib.acl_get_fd_np.side_effect = absent
            with self.subTest(error=error), patch.object(installer, "acl_library", return_value=lib):
                if error == errno.ENOENT:
                    installer.validate_acl_fd(7)
                else:
                    with self.assertRaises(ValueError):
                        installer.validate_acl_fd(7)
            lib.acl_free.assert_not_called()

    def test_safe_allow_and_deny_entries_preserved(self):
        for entries in ([], [(2, 1 << 4)], [(1, installer.ACL_SAFE_ALLOW)], [(2, (1 << 64) - 1)]):
            lib = self.library(entries)
            with patch.object(installer, "acl_library", return_value=lib):
                installer.validate_acl_fd(7)
            lib.acl_free.assert_called_once_with(123)

    def test_every_mutation_right_unknown_right_and_tag_refused_and_freed(self):
        for entry in [(1, 1 << bit) for bit in (2, 4, 5, 6, 8, 10, 12, 13, 63)] + [(3, 0)]:
            lib = self.library([entry])
            with self.subTest(entry=entry), patch.object(installer, "acl_library", return_value=lib), self.assertRaises(ValueError):
                installer.validate_acl_fd(7)
            lib.acl_free.assert_called_once_with(123)

    def test_invalid_unreadable_and_oversized_acls_fail_closed(self):
        for function in ("acl_valid", "acl_get_entry", "acl_get_tag_type", "acl_get_permset_mask_np"):
            lib = self.library([(2, 16)])
            getattr(lib, function).side_effect = lambda *args: -1
            with self.subTest(function=function), patch.object(installer, "acl_library", return_value=lib), self.assertRaises(ValueError):
                installer.validate_acl_fd(7)
            lib.acl_free.assert_called_once_with(123)
        for count in (128, 129):
            lib = self.library([(2, 16)] * count)
            with patch.object(installer, "acl_library", return_value=lib):
                if count == 128:
                    installer.validate_acl_fd(7)
                else:
                    with self.assertRaises(ValueError):
                        installer.validate_acl_fd(7)
            self.assertLessEqual(lib.acl_get_entry.call_count, 129)
            lib.acl_free.assert_called_once_with(123)

    def test_missing_native_api_and_non_darwin_fail_closed(self):
        with patch.object(installer.sys, "platform", "linux"), self.assertRaises(ValueError):
            installer.acl_library()
        with patch.object(installer.sys, "platform", "darwin"), patch.object(installer.ctypes, "CDLL", side_effect=OSError()), self.assertRaises(ValueError):
            installer.acl_library()
        with patch.object(installer.sys, "platform", "darwin"), patch.object(installer.ctypes, "CDLL", return_value=object()), self.assertRaises(ValueError):
            installer.acl_library()

    @unittest.skipUnless(sys.platform == "darwin", "native Darwin ACL ABI")
    def test_native_in_memory_inherited_acl_classification(self):
        # These APIs modify only an allocated ACL, never a filesystem ACL.
        lib = installer.acl_library()
        pointer = ctypes.c_void_p
        for name, arguments, result in (
            ("acl_init", [ctypes.c_int], pointer),
            ("acl_create_entry", [ctypes.POINTER(pointer), ctypes.POINTER(pointer)], ctypes.c_int),
            ("acl_set_tag_type", [pointer, ctypes.c_int], ctypes.c_int),
            ("acl_set_permset_mask_np", [pointer, ctypes.c_uint64], ctypes.c_int),
            ("acl_get_flagset_np", [pointer, ctypes.POINTER(pointer)], ctypes.c_int),
            ("acl_add_flag_np", [pointer, ctypes.c_int], ctypes.c_int),
        ):
            function = getattr(lib, name)
            function.argtypes, function.restype = arguments, result
        for flag in (0, 1 << 4, (1 << 5) | (1 << 6) | (1 << 8)):
            for tag, rights, allowed in ((2, 16, True), (1, installer.ACL_SAFE_ALLOW, True), (1, 4, False), (1, 64, False)):
                with self.subTest(flag=flag, tag=tag, rights=rights):
                    acl = pointer(lib.acl_init(1))
                    self.assertTrue(acl.value)
                    try:
                        entry, flags = pointer(), pointer()
                        self.assertEqual(lib.acl_create_entry(ctypes.byref(acl), ctypes.byref(entry)), 0)
                        self.assertEqual(lib.acl_set_tag_type(entry, tag), 0)
                        self.assertEqual(lib.acl_set_permset_mask_np(entry, rights), 0)
                        self.assertEqual(lib.acl_get_flagset_np(entry, ctypes.byref(flags)), 0)
                        if flag:
                            self.assertEqual(lib.acl_add_flag_np(flags, flag), 0)
                        if allowed:
                            installer.validate_acl_entries(lib, acl)
                        else:
                            with self.assertRaises(ValueError):
                                installer.validate_acl_entries(lib, acl)
                    finally:
                        lib.acl_free(acl)


if __name__ == "__main__":
    unittest.main()
