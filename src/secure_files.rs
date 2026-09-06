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

/// Writes sensitive bytes to disk and then applies the platform's strongest
/// local owner-only protection available to WispKey.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_private_directory(parent)?;
    }
    write_private_file(path, bytes)?;
    harden_file(path)
}

/// Restricts an existing sensitive file to the current user.
pub(crate) fn harden_existing_file(path: &Path) -> Result<()> {
    harden_file(path)
}

/// Appends sensitive bytes to disk and then applies owner-only protection.
pub(crate) fn append_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_private_directory(parent)?;
    }
    append_private_file(path, bytes)?;
    harden_file(path)
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

/// Reads a small sensitive text file after rejecting obviously unsafe inputs
/// such as directories, oversized files, and broad Unix permissions.
pub(crate) fn read_private_string(path: &Path, max_bytes: u64) -> Result<String> {
    let metadata = fs::metadata(path)?;
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
    validate_private_file(path, &metadata)?;
    fs::read_to_string(path).map_err(VaultError::from)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
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

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn append_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new().append(true).create(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
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
fn validate_private_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
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
fn validate_private_file(path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    windows_acl::apply_private_acl(path)
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
fn validate_private_file(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub(crate) mod windows_acl {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, PSECURITY_DESCRIPTOR, SetFileSecurityW,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::core::{Result, VaultError};

    pub(super) fn apply_private_acl(path: &Path) -> Result<()> {
        let sid = current_user_sid_string()?;
        let sddl = format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)");
        let descriptor = security_descriptor_from_sddl(&sddl)?;
        let path_wide = wide_null(path.as_os_str());

        let set_result = unsafe {
            SetFileSecurityW(path_wide.as_ptr(), DACL_SECURITY_INFORMATION, descriptor.0)
        };
        if set_result == 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    fn current_user_sid_string() -> Result<String> {
        let mut token: HANDLE = null_mut();
        let opened =
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token as *mut _) };
        if opened == 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
        let token = Handle(token);

        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed as *mut _);
        }
        if needed == 0 {
            return Err(VaultError::Io(std::io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32,
            )));
        }

        let mut buffer = vec![0u8; needed as usize];
        let read = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed as *mut _,
            )
        };
        if read == 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }

        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut sid_ptr = null_mut();
        let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_ptr) };
        if converted == 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
        let sid = unsafe { wide_ptr_to_string(sid_ptr) };
        unsafe {
            LocalFree(sid_ptr.cast());
        }
        Ok(sid)
    }

    fn security_descriptor_from_sddl(sddl: &str) -> Result<SecurityDescriptor> {
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

    unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf16_lossy(slice)
    }

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(crate) fn current_user_only_security_descriptor() -> Result<SecurityDescriptor> {
        let sid = current_user_sid_string()?;
        security_descriptor_from_sddl(&format!("D:P(A;;GA;;;{sid})"))
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
