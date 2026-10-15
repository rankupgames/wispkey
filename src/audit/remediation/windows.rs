//! Windows remediation uses pinned, non-reparse local paths and a private DACL
//! supplied to CREATE_NEW. It never repairs ACLs or resolves a path after writing.
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_TYPE_DISK, GetDriveTypeW,
    GetFileInformationByHandle, GetFileType, OPEN_EXISTING, READ_CONTROL,
};

use super::{MAX_INPUT_BYTES, RemediationReport, sanitize};
use crate::secure_files::{windows_acl, windows_private};

// GetDriveTypeW return value from the Windows SDK.
const DRIVE_FIXED: u32 = 3;

const UNSAFE_PATH: &str = "path must be a normal local disk path without links or streams";
const UNSAFE_INPUT: &str = "input must be a private owner-owned regular file with no hard links";

/// Keep every directory handle alive until the new file has been synced. A
/// directory handle without FILE_SHARE_DELETE prevents renames/deletion, including
/// ancestors; opening each child only after its ancestors are pinned closes the
/// usual check-by-path/open-by-path race. Directory contents can still change:
/// OPEN_REPARSE_POINT and CREATE_NEW independently protect the final components.
struct PinnedParent {
    path: PathBuf,
    directories: Vec<File>,
}

fn normal_path(path: &Path) -> Result<PathBuf, String> {
    // Reject drive-relative paths before joining to the process directory.
    if path.has_root() && !path.is_absolute()
        || matches!(path.components().next(), Some(Component::Prefix(_))) && !path.is_absolute()
    {
        return Err(UNSAFE_PATH.into());
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|_| UNSAFE_PATH)?.join(path)
    };
    let mut components = absolute.components();
    if !matches!(components.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        // UNC, verbatim/device namespaces and mapped network roots fail closed.
        return Err(UNSAFE_PATH.into());
    }
    let root: PathBuf = absolute.components().take(2).collect();
    let root_wide: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
    // Network filesystems do not necessarily supply local NTFS sharing/ACL semantics.
    if unsafe { GetDriveTypeW(root_wide.as_ptr()) } != DRIVE_FIXED {
        return Err(UNSAFE_PATH.into());
    }
    for part in components {
        let Component::Normal(name) = part else {
            return Err(UNSAFE_PATH.into());
        };
        let name = name.to_str().ok_or(UNSAFE_PATH)?;
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if name.is_empty()
            || name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|c| c <= '\u{1f}' || "<>:\"/\\|?*".contains(c))
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || stem
                .strip_prefix("COM")
                .or_else(|| stem.strip_prefix("LPT"))
                .is_some_and(|n| {
                    matches!(
                        n,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
        {
            return Err(UNSAFE_PATH.into());
        }
    }
    Ok(absolute)
}

fn open(
    path: &Path,
    access: u32,
    share: u32,
    creation: u32,
    security: Option<&windows_acl::SecurityDescriptor>,
) -> Result<File, String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let attributes = security.map(|descriptor| SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_mut_ptr(),
        bInheritHandle: 0,
    });
    // SAFETY: terminated validated path and optional descriptor remain alive for
    // the call. The returned handle has unique ownership and is never inherited.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share,
            attributes.as_ref().map_or(std::ptr::null(), |a| a),
            creation,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                "output already exists; choose a new file"
            } else {
                "cannot open protected file or directory"
            }
            .into(),
        );
    }
    // SAFETY: successful CreateFileW transfers one owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn information(file: &File, directory: bool) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: file owns a live handle, info is writable storage of the API type.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(UNSAFE_PATH.into());
    }
    Ok(info)
}

impl PinnedParent {
    fn open(path: &Path, private: bool) -> Result<Self, String> {
        let mut prefix = PathBuf::new();
        let mut directories = Vec::new();
        for part in path.components() {
            prefix.push(part);
            if matches!(part, Component::Prefix(_)) {
                continue;
            }
            let file = open(
                &prefix,
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                None,
            )?;
            information(&file, true)?;
            directories.push(file);
        }
        let parent = directories.last().ok_or(UNSAFE_PATH)?;
        if private {
            windows_private::verify_acl(parent)
                .map_err(|_| "output directory must be private and owned by the current user")?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            directories,
        })
    }

    fn create(&self, name: &std::ffi::OsStr, bytes: &[u8]) -> Result<(), String> {
        // The parent and all ancestors are still pinned while using this path.
        let descriptor = windows_acl::current_user_owned_security_descriptor()
            .map_err(|_| "cannot construct private output protection")?;
        let mut file = open(
            &self.path.join(name),
            GENERIC_WRITE | READ_CONTROL,
            0,
            CREATE_NEW,
            Some(&descriptor),
        )?;
        let info = information(&file, false)?;
        if info.nNumberOfLinks != 1 {
            return Err("unsafe output file".into());
        }
        windows_private::verify_acl(&file)
            .map_err(|_| "cannot verify private output protection")?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "cannot complete output; a partial protected copy may remain")?;
        // Windows does not provide a portable directory fsync equivalent.
        debug_assert!(!self.directories.is_empty());
        Ok(())
    }
}

pub(super) fn remediate(input: &Path, output: &Path) -> Result<RemediationReport, String> {
    let input = normal_path(input)?;
    let output = normal_path(output)?;
    let _source_parent = PinnedParent::open(input.parent().ok_or(UNSAFE_PATH)?, false)?;
    let target_parent = PinnedParent::open(output.parent().ok_or(UNSAFE_PATH)?, true)?;
    // Deny new or existing write/delete access for the lifetime of this handle.
    let mut file = open(
        &input,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        None,
    )?;
    let info = information(&file, false)?;
    let length = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if info.nNumberOfLinks != 1 || length > MAX_INPUT_BYTES {
        return Err(UNSAFE_INPUT.into());
    }
    windows_private::verify_acl(&file).map_err(|_| UNSAFE_INPUT)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read input")?;
    let after = information(&file, false)?;
    if bytes.len() as u64 != length
        || bytes.len() as u64 > MAX_INPUT_BYTES
        || after.nNumberOfLinks != 1
        || after.nFileSizeHigh != info.nFileSizeHigh
        || after.nFileSizeLow != info.nFileSizeLow
        || after.ftLastWriteTime.dwHighDateTime != info.ftLastWriteTime.dwHighDateTime
        || after.ftLastWriteTime.dwLowDateTime != info.ftLastWriteTime.dwLowDateTime
    {
        return Err("input changed while reading; use an offline snapshot".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "input is not UTF-8 JSONL")?;
    let (sanitized, report) = sanitize(text)?;
    target_parent.create(output.file_name().ok_or(UNSAFE_PATH)?, &sanitized)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    // All ACLs in these tests belong to newly created synthetic temporary
    // fixtures. No existing directory, account, vault or OS setting is changed.
    fn directory(path: &Path, descriptor: &windows_acl::SecurityDescriptor) {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_mut_ptr(),
            bInheritHandle: 0,
        };
        assert_ne!(unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) }, 0);
    }

    fn write(path: &Path, bytes: &[u8], descriptor: &windows_acl::SecurityDescriptor) {
        let mut file = open(
            path,
            GENERIC_WRITE | READ_CONTROL,
            0,
            CREATE_NEW,
            Some(descriptor),
        )
        .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private");
        let descriptor = windows_acl::current_user_owned_security_descriptor().unwrap();
        directory(&private, &descriptor);
        let input = private.join("legacy.jsonl");
        write(
            &input,
            super::super::tests::legacy().as_bytes(),
            &descriptor,
        );
        let output = private.join("safe.jsonl");
        (root, input, output)
    }

    #[test]
    fn preserves_source_and_creates_private_copy_exclusively() {
        let (_root, input, output) = fixture();
        let original = fs::read(&input).unwrap();
        let report = remediate(&input, &output).unwrap();
        assert!(report.source_preserved);
        assert_eq!(report.records_written, 1);
        assert_eq!(report.legacy_token_fields_removed, 1);
        assert_eq!(fs::read(&input).unwrap(), original);
        let file = open(
            &output,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            None,
        )
        .unwrap();
        windows_private::verify_acl(&file).unwrap();
        // Stronger than the accepted-input ACL policy: newly created output
        // has exactly one explicit grant, with no inherited SYSTEM/admin ACEs.
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        assert_eq!(
            unsafe {
                windows_sys::Win32::Security::Authorization::GetSecurityInfo(
                    file.as_raw_handle(),
                    windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT,
                    windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut dacl,
                    null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        assert!(!dacl.is_null());
        assert_eq!(unsafe { (*dacl).AceCount }, 1);
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            unsafe {
                windows_sys::Win32::Security::GetSecurityDescriptorControl(
                    descriptor,
                    &mut control,
                    &mut revision,
                )
            },
            0
        );
        assert_ne!(control & windows_sys::Win32::Security::SE_DACL_PROTECTED, 0);
        let mut ace = null_mut();
        assert_ne!(
            unsafe { windows_sys::Win32::Security::GetAce(dacl, 0, &mut ace) },
            0
        );
        let allowed = unsafe { &*(ace.cast::<windows_sys::Win32::Security::ACCESS_ALLOWED_ACE>()) };
        assert_eq!(allowed.Header.AceType, 0); // ACCESS_ALLOWED_ACE_TYPE
        assert_eq!(allowed.Header.AceFlags, 0); // explicit, non-inherited, non-inheritable
        let sid = windows_private::current_sid_string().unwrap();
        let sid_wide: Vec<u16> = sid.encode_utf16().chain(Some(0)).collect();
        let mut current_sid = null_mut();
        assert_ne!(
            unsafe {
                windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(
                    sid_wide.as_ptr(),
                    &mut current_sid,
                )
            },
            0
        );
        assert_ne!(
            unsafe {
                windows_sys::Win32::Security::EqualSid(
                    (&allowed.SidStart as *const u32).cast_mut().cast(),
                    current_sid,
                )
            },
            0
        );
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(current_sid);
        }
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(descriptor);
        }
        assert_eq!(information(&file, false).unwrap().nNumberOfLinks, 1);
        drop(file);
        let clean = fs::read(&output).unwrap();
        assert!(!String::from_utf8_lossy(&clean).contains("wk_"));
        let second = output.with_file_name("second.jsonl");
        remediate(&output, &second).unwrap();
        assert_eq!(fs::read(second).unwrap(), clean);
        assert!(remediate(&input, &output).is_err());
        assert!(remediate(&input, &input).is_err());
        assert_eq!(fs::read(&input).unwrap(), original);
        assert_eq!(fs::read(&output).unwrap(), clean);
    }

    #[test]
    fn rejects_broad_and_null_acl_files_and_output_directories() {
        for dacl in ["D:P(A;;FA;;;WD)", "D:NO_ACCESS_CONTROL"] {
            let (root, input, output) = fixture();
            let sid = windows_private::current_sid_string().unwrap();
            let descriptor =
                windows_acl::security_descriptor_from_sddl(&format!("O:{sid}{dacl}")).unwrap();
            let broad = root.path().join("broad.jsonl");
            write(
                &broad,
                super::super::tests::legacy().as_bytes(),
                &descriptor,
            );
            assert!(remediate(&broad, &output).is_err());
            assert!(!output.exists());
            let broad_dir = root.path().join("broad-directory");
            directory(&broad_dir, &descriptor);
            let rejected_output = broad_dir.join("out.jsonl");
            assert!(remediate(&input, &rejected_output).is_err());
            assert!(!rejected_output.exists());
        }
    }

    #[test]
    fn rejects_hard_links_oversize_and_existing_destination_links() {
        let (_root, input, output) = fixture();
        let linked = input.with_file_name("hard.jsonl");
        fs::hard_link(&input, &linked).unwrap();
        assert!(remediate(&input, &output).is_err());
        fs::remove_file(linked).unwrap();
        let unrelated = input.with_file_name("unrelated");
        fs::write(&unrelated, b"synthetic unrelated content").unwrap();
        fs::hard_link(&unrelated, &output).unwrap();
        assert!(remediate(&input, &output).is_err());
        assert_eq!(
            fs::read(&unrelated).unwrap(),
            b"synthetic unrelated content"
        );
        fs::remove_file(&output).unwrap();
        let file = fs::OpenOptions::new().write(true).open(&input).unwrap();
        file.set_len(MAX_INPUT_BYTES + 1).unwrap();
        drop(file);
        assert!(remediate(&input, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn rejects_unsafe_windows_path_names() {
        for path in [
            r"\\server\share\in",
            r"\\?\C:\in",
            r"\\.\C:\in",
            r"C:in",
            r"\in",
            r"C:\in:stream",
            r"C:\dir\..\in",
            r"C:\dir.\in",
            r"C:\dir \in",
            r"C:\NUL.jsonl",
            r"C:\COM1",
            r"C:\LPT².txt",
            r"C:\CONIN$",
            "C:\\in\0ignored",
        ] {
            assert!(
                normal_path(Path::new(path)).is_err(),
                "unexpected accepted path"
            );
        }
    }

    #[test]
    fn rejects_malformed_utf8_and_records_before_creation() {
        for data in [
            vec![0xff, 0xfe],
            b"wk_synthetic_invalid".to_vec(),
            format!(
                "{}\n{{\"denied\":\"wk_synthetic_invalid\"}}\n",
                super::super::tests::legacy()
            )
            .into_bytes(),
        ] {
            let (_root, input, output) = fixture();
            fs::write(&input, &data).unwrap();
            let error = remediate(&input, &output).unwrap_err();
            assert!(!error.contains("wk_"));
            assert!(!output.exists());
            assert_eq!(fs::read(&input).unwrap(), data);
        }
    }

    #[test]
    fn pins_ancestors_against_concurrent_rename_and_source_against_writers() {
        let (root, input, output) = fixture();
        let parent = output.parent().unwrap();
        let pinned = PinnedParent::open(parent, true).unwrap();
        // A writable directory handle used to change a reparse point is denied.
        assert!(open(parent, GENERIC_WRITE, FILE_SHARE_READ, OPEN_EXISTING, None).is_err());
        let rename_parent = parent.to_path_buf();
        let renamed = root.path().join("moved");
        std::thread::spawn(move || {
            assert!(fs::rename(rename_parent, renamed).is_err());
        })
        .join()
        .unwrap();
        let root_path = root.path().to_path_buf();
        let moved_root = root.path().with_extension("moved");
        std::thread::spawn(move || {
            assert!(fs::rename(root_path, moved_root).is_err());
        })
        .join()
        .unwrap();
        let file = open(
            &input,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            None,
        )
        .unwrap();
        let source = input.clone();
        std::thread::spawn(move || {
            assert!(fs::OpenOptions::new().write(true).open(&source).is_err());
            assert!(fs::rename(&source, source.with_extension("moved")).is_err());
            assert!(fs::remove_file(&source).is_err());
        })
        .join()
        .unwrap();
        pinned.create(output.file_name().unwrap(), b"{}\n").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"{}\n");
        drop(file);
        drop(pinned);
        fs::remove_file(&output).unwrap();
        let writer = fs::OpenOptions::new().write(true).open(&input).unwrap();
        assert!(remediate(&input, &output).is_err());
        assert!(!output.exists());
        drop(writer);
        remediate(&input, &output).unwrap();
    }

    #[test]
    fn rejects_junctions_in_source_and_destination_ancestors() {
        let (root, input, _output) = fixture();
        let junction = root.path().join("junction");
        // Junction fixtures require no developer mode or symlink privilege.
        let result = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(input.parent().unwrap())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "could not create synthetic junction fixture"
        );
        assert!(
            remediate(
                &junction.join("legacy.jsonl"),
                &input.with_file_name("safe.jsonl")
            )
            .is_err()
        );
        assert!(remediate(&input, &junction.join("safe.jsonl")).is_err());
        assert!(!input.with_file_name("safe.jsonl").exists());
        fs::remove_dir(&junction).unwrap();
    }

    #[test]
    fn simultaneous_outputs_have_only_one_winner() {
        let (_root, input, output) = fixture();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let input = input.clone();
                let output = output.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    remediate(&input, &output).is_ok()
                })
            })
            .collect();
        let successes = threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>();
        assert_eq!(successes, 1);
        assert!(!fs::read_to_string(output).unwrap().contains("wk_"));
    }
}
