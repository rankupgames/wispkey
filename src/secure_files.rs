/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Cross-platform helpers for writing and validating sensitive
 *              local files with restrictive owner-only permissions.
 * Created: 2026-05-16
 * Last Modified: 2026-05-16
 */

use std::fs;
use std::path::Path;

use crate::core::{Result, VaultError};

/// Creates a directory tree and restricts access to the current user where the
/// operating system exposes portable file protection primitives.
pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    harden_directory(path)
}

/// Atomically replaces a file with a complete, privately created payload.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    replace_private(path, bytes)
}

/// Restricts an existing sensitive file to the current user.
pub(crate) fn harden_existing_file(path: &Path) -> Result<()> {
    harden_file(path)
}

/// Appends sensitive bytes only to a private file, creating it privately if absent.
pub(crate) fn append_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_private_directory(parent)?;
    }
    append_private_file(path, bytes)
}

/// Creates a new owner-only file without replacing an existing file.
/// Returns `false` when another process created the file first.
pub(crate) fn create_private(path: &Path, bytes: &[u8]) -> Result<bool> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_private_directory(parent)?;
    }
    create_private_in_existing_directory(path, bytes)
}

/// Atomically replaces a small private state file with a complete payload.
pub(crate) fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        ensure_private_directory(parent)?;
    }
    let parent = parent.unwrap_or(Path::new("."));
    let staged = parent.join(format!(".wk-replace-{}", uuid::Uuid::new_v4()));
    if !create_private_in_existing_directory(&staged, bytes)? {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "replacement staging exists",
        )));
    }
    let result = (|| {
        fs::OpenOptions::new()
            .write(true)
            .open(&staged)?
            .sync_all()?;
        fs::rename(&staged, path)?;
        Ok(())
    })();
    if staged.exists() {
        fs::remove_file(&staged)?;
    }
    result
}

/// Creates a new private file without changing permissions on its existing
/// parent directory. Returns `false` if the file already exists.
pub(crate) fn create_private_in_existing_directory(path: &Path, bytes: &[u8]) -> Result<bool> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("parent directory does not exist: {}", parent.display()),
        )));
    }
    match create_private_file(path, bytes) {
        Ok(()) => {
            if let Err(error) = harden_file(path) {
                let _ = fs::remove_file(path);
                return Err(error);
            }
            Ok(true)
        }
        Err(VaultError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Reports whether a directory uses owner-only protection, without changing it.
pub(crate) fn inspect_private_directory(path: &Path) -> std::result::Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    inspect_private_metadata(path, &metadata, true)
}

/// Reports whether a file uses owner-only protection, without changing it.
pub(crate) fn inspect_private_file(path: &Path) -> std::result::Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    inspect_private_metadata(path, &metadata, false)
}

/// Reports whether this platform can verify private-file metadata without
/// adding a platform-specific ACL inspection implementation.
pub(crate) fn private_metadata_inspection_supported() -> bool {
    cfg!(unix)
}

#[cfg(unix)]
fn inspect_private_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    is_directory: bool,
) -> std::result::Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    let expected = if is_directory { 0o700 } else { 0o600 };
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} has permissions {:04o}; expected owner-only ({:04o})",
            path.display(),
            mode,
            expected
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn inspect_private_metadata(
    path: &Path,
    _metadata: &fs::Metadata,
    _is_directory: bool,
) -> std::result::Result<(), String> {
    Err(format!(
        "{} owner-only permission inspection is unsupported on this platform",
        path.display()
    ))
}

/// Reads a bounded sensitive text file without changing its permissions.
pub(crate) fn read_private_string(path: &Path, max_bytes: u64) -> Result<String> {
    use std::io::Read;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(VaultError::InvalidBundle(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes {
        return Err(VaultError::InvalidBundle(format!(
            "{} exceeds the size limit",
            path.display()
        )));
    }
    validate_private_file(path, &metadata, &file)?;
    let mut text = String::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_string(&mut text)?;
    if text.len() as u64 > max_bytes {
        return Err(VaultError::InvalidBundle(format!(
            "{} exceeds the size limit",
            path.display()
        )));
    }
    Ok(text)
}

#[cfg(unix)]
fn append_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    validate_private_file(path, &file.metadata()?, &file)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn append_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new().append(true).create(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(windows)]
fn open_private_file(path: &Path, creation: u32, access: u32) -> Result<fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let descriptor = windows_acl::private_file_security_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_mut_ptr(),
        bInheritHandle: 0,
    };
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL").into(),
        );
    }
    wide.push(0);
    // SAFETY: the path and descriptor remain valid for the call. The new handle
    // is not inherited; creation publishes a private DACL before any bytes.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            creation,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let creation_status = unsafe { GetLastError() };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::from_raw_os_error(creation_status as i32).into());
    }
    // SAFETY: a successful CreateFileW returns an owned file handle.
    let file = unsafe { fs::File::from_raw_handle(handle) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(VaultError::InvalidBundle(
            "private output must be a regular file".into(),
        ));
    }
    if creation == CREATE_NEW || creation_status != ERROR_ALREADY_EXISTS {
        return Ok(file);
    }
    windows_private::verify_acl(&file)
        .map_err(|message| VaultError::InvalidBundle(message.into()))?;
    Ok(file)
}

#[cfg(windows)]
fn append_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_WRITE, FILE_WRITE_DATA, OPEN_ALWAYS,
    };

    // Match OpenOptions::append: retain metadata/security query rights while
    // omitting FILE_WRITE_DATA so each write is atomically appended by Windows.
    let mut file = open_private_file(path, OPEN_ALWAYS, FILE_GENERIC_WRITE & !FILE_WRITE_DATA)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(windows)]
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use windows_sys::Win32::Foundation::GENERIC_WRITE;
    use windows_sys::Win32::Storage::FileSystem::CREATE_NEW;

    let mut file = open_private_file(path, CREATE_NEW, GENERIC_WRITE)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(unix)]
fn harden_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn harden_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(path: &Path, metadata: &fs::Metadata, _file: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(VaultError::InvalidBundle(format!(
            "{} must not be readable, writable, or executable by group/other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn harden_directory(path: &Path) -> Result<()> {
    windows_acl::apply_private_acl(path)
}

#[cfg(windows)]
fn harden_file(path: &Path) -> Result<()> {
    windows_acl::apply_private_acl(path)
}

#[cfg(windows)]
fn validate_private_file(path: &Path, metadata: &fs::Metadata, file: &fs::File) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(VaultError::InvalidBundle(format!(
            "{} must not be a reparse point",
            path.display()
        )));
    }
    windows_private::verify_acl(file)
        .map_err(|message| VaultError::InvalidBundle(format!("{}: {message}", path.display())))
}

#[cfg(all(not(unix), not(windows)))]
fn harden_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn harden_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_private_file(_path: &Path, _metadata: &fs::Metadata, _file: &fs::File) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub(crate) mod windows_acl {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
    };

    use crate::core::{Result, VaultError};

    pub(super) fn apply_private_acl(path: &Path) -> Result<()> {
        let descriptor = private_file_security_descriptor()?;
        let path_wide = wide_null(path.as_os_str());

        let set_result = unsafe {
            SetFileSecurityW(path_wide.as_ptr(), DACL_SECURITY_INFORMATION, descriptor.0)
        };
        if set_result == 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    pub(super) fn private_file_security_descriptor() -> Result<SecurityDescriptor> {
        let sid = current_user_sid_string()?;
        security_descriptor_from_sddl(&format!(
            "O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        ))
    }

    fn current_user_sid_string() -> Result<String> {
        super::windows_private::current_sid_string()
            .map_err(|message| VaultError::Io(std::io::Error::other(message)))
    }

    pub(crate) fn security_descriptor_from_sddl(sddl: &str) -> Result<SecurityDescriptor> {
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor as *mut _,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
        Ok(SecurityDescriptor(descriptor))
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub(crate) fn current_user_only_security_descriptor() -> Result<SecurityDescriptor> {
        let sid = current_user_sid_string()?;
        security_descriptor_from_sddl(&format!("D:P(A;;GA;;;{sid})"))
    }

    /// Explicit owner avoids an elevated token defaulting ownership to Administrators.
    pub(crate) fn current_user_owned_security_descriptor() -> Result<SecurityDescriptor> {
        let sid = super::windows_private::current_sid_string()
            .map_err(|message| VaultError::Io(std::io::Error::other(message)))?;
        security_descriptor_from_sddl(&format!("O:{sid}D:P(A;;GA;;;{sid})"))
    }

    pub(crate) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl SecurityDescriptor {
        pub(crate) fn as_mut_ptr(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

#[cfg(windows)]
pub(crate) mod windows_private;

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use std::io::Read;

    #[cfg(unix)]
    pub(super) fn make_broad(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[cfg(windows)]
    pub(super) fn make_broad(path: &Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, SetFileSecurityW};

        let sid = windows_private::current_sid_string().unwrap();
        let descriptor =
            windows_acl::security_descriptor_from_sddl(&format!("D:P(A;;FA;;;{sid})(A;;FR;;;WD)"))
                .unwrap();
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    wide.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    descriptor.as_mut_ptr(),
                )
            },
            0
        );
    }

    #[cfg(unix)]
    fn protection(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode()
    }

    #[cfg(windows)]
    fn protection(path: &Path) -> Vec<usize> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetFileSecurityW};

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut needed = 0;
        unsafe {
            GetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        assert!(needed > 0);
        let mut descriptor = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetFileSecurityW(
                    wide.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    descriptor.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            },
            0
        );
        descriptor
    }

    #[test]
    fn private_write_keeps_replacement_bytes_out_of_preopened_readers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing-output");
        fs::write(&path, b"old-public-fixture").unwrap();
        make_broad(&path);
        let mut prior_reader = fs::File::open(&path).unwrap();
        write_private(&path, b"new-private-fixture").unwrap();
        let mut prior_bytes = String::new();
        prior_reader.read_to_string(&mut prior_bytes).unwrap();
        assert_eq!(prior_bytes, "old-public-fixture");
        assert_eq!(
            read_private_string(&path, 128).unwrap(),
            "new-private-fixture"
        );
    }

    #[test]
    fn append_rejects_unsafe_existing_file_without_changing_bytes_or_protection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unsafe-append");
        fs::write(&path, b"old-public-fixture").unwrap();
        make_broad(&path);
        let prior_protection = protection(&path);
        assert!(append_private(&path, b"new-private-fixture").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old-public-fixture");
        assert_eq!(protection(&path), prior_protection);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::io::Write;
    use windows_sys::Win32::Foundation::GENERIC_WRITE;
    use windows_sys::Win32::Storage::FileSystem::CREATE_NEW;

    #[test]
    fn private_read_rejects_broad_acl_without_repair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("supplied-passphrase");
        let bytes = b"synthetic-private-file-fixture";
        fs::write(&path, bytes).unwrap();
        super::tests::make_broad(&path);
        assert!(windows_private::verify_acl(&fs::File::open(&path).unwrap()).is_err());
        assert!(read_private_string(&path, 128).is_err());
        assert!(windows_private::verify_acl(&fs::File::open(&path).unwrap()).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn private_creation_protects_empty_file_before_writing_and_preserves_writer_modes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private-output");
        let mut file = open_private_file(&path, CREATE_NEW, GENERIC_WRITE).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
        windows_private::verify_acl(&fs::File::open(&path).unwrap()).unwrap();
        file.write_all(b"first").unwrap();
        drop(file);
        append_private(&path, b"-second").unwrap();
        assert_eq!(read_private_string(&path, 128).unwrap(), "first-second");
        write_private(&path, b"replacement").unwrap();
        assert_eq!(read_private_string(&path, 128).unwrap(), "replacement");
        assert!(!create_private_in_existing_directory(&path, b"must-not-replace").unwrap());
        assert_eq!(read_private_string(&path, 128).unwrap(), "replacement");
    }
}
