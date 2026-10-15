//! Local OS identity and bounded, private operation-catalog input.
//!
//! The principal identifies the local process account. It is descriptive
//! preflight metadata, not an agent or sandbox authorization decision.

#[cfg(windows)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const MAX_CATALOG_BYTES: u64 = 64 * 1024;
const INVALID_CATALOG: &str = "operation catalog is unavailable or unsafe";

#[cfg(unix)]
pub(crate) fn current_principal() -> Result<String, &'static str> {
    // SAFETY: geteuid has no arguments or mutable process state.
    Ok(format!("unix-uid:{}", unsafe { libc::geteuid() }))
}

#[cfg(windows)]
pub(crate) fn current_principal() -> Result<String, &'static str> {
    Ok(format!(
        "windows-sid:{}",
        windows_private::current_sid_string()?
    ))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn current_principal() -> Result<String, &'static str> {
    Err("local OS principal is unavailable")
}

/// Reads the exact handle whose type, size, owner, and protection were checked.
/// No path, file content, or operating-system error is included in failures.
pub(crate) fn read_private_catalog(path: &Path) -> Result<String, &'static str> {
    reject_linked_components(path)?;
    let mut file = open_catalog(path)?;
    let metadata = file.metadata().map_err(|_| INVALID_CATALOG)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CATALOG_BYTES {
        return Err(INVALID_CATALOG);
    }
    verify_file_protection(&file, &metadata)?;

    // `take` also bounds a file that grows after metadata inspection.
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_CATALOG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID_CATALOG)?;
    if bytes.len() as u64 > MAX_CATALOG_BYTES {
        return Err(INVALID_CATALOG);
    }
    String::from_utf8(bytes).map_err(|_| INVALID_CATALOG)
}

fn reject_linked_components(path: &Path) -> Result<(), &'static str> {
    use std::path::{Component, PathBuf};
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| INVALID_CATALOG)?
            .join(path)
    };
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        if matches!(component, Component::ParentDir) {
            return Err(INVALID_CATALOG);
        }
        prefix.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&prefix).map_err(|_| INVALID_CATALOG)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(INVALID_CATALOG);
        }
        if prefix != absolute && !metadata.is_dir() {
            return Err(INVALID_CATALOG);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn open_catalog(path: &Path) -> Result<File, &'static str> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| INVALID_CATALOG)?
            .join(path)
    };
    let mut directory = File::open("/").map_err(|_| INVALID_CATALOG)?;
    let mut parts = absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Ok(name)),
            Component::ParentDir => Some(Err(INVALID_CATALOG)),
            _ => None,
        })
        .peekable();
    while let Some(part) = parts.next() {
        let name = CString::new(part?.as_bytes()).map_err(|_| INVALID_CATALOG)?;
        let final_part = parts.peek().is_none();
        let flags = if final_part {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        // SAFETY: directory is a live descriptor; name is NUL-terminated.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(INVALID_CATALOG);
        }
        // SAFETY: successful openat returns an owned descriptor.
        let opened = unsafe { File::from_raw_fd(fd) };
        if final_part {
            return Ok(opened);
        }
        directory = opened;
    }
    Err(INVALID_CATALOG)
}

#[cfg(windows)]
fn open_catalog(path: &Path) -> Result<File, &'static str> {
    use std::os::windows::fs::OpenOptionsExt;
    // OPEN_REPARSE_POINT lets the handle metadata reveal a final reparse point.
    OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
        .open(path)
        .map_err(|_| INVALID_CATALOG)
}

#[cfg(not(any(unix, windows)))]
fn open_catalog(_path: &Path) -> Result<File, &'static str> {
    Err(INVALID_CATALOG)
}

#[cfg(unix)]
fn verify_file_protection(_file: &File, metadata: &fs::Metadata) -> Result<(), &'static str> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Root may inspect an owner's file, but must not silently relabel it as
    // belonging to the runner principal.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(INVALID_CATALOG);
    }
    Ok(())
}

#[cfg(windows)]
fn verify_file_protection(file: &File, metadata: &fs::Metadata) -> Result<(), &'static str> {
    if is_reparse_point(metadata) {
        return Err(INVALID_CATALOG);
    }
    windows_private::verify_acl(file).map_err(|_| INVALID_CATALOG)
}

#[cfg(not(any(unix, windows)))]
fn verify_file_protection(_file: &File, _metadata: &fs::Metadata) -> Result<(), &'static str> {
    Err(INVALID_CATALOG)
}

#[cfg(windows)]
use crate::secure_files::windows_private;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_comes_from_os() {
        let principal = current_principal().unwrap();
        #[cfg(unix)]
        assert_eq!(
            principal,
            format!("unix-uid:{}", unsafe { libc::geteuid() })
        );
        #[cfg(windows)]
        assert!(principal.starts_with("windows-sid:S-1-"));
    }

    #[test]
    fn bounded_private_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("operations.toml");
        fs::write(&path, "[[operations]]\nname = 'hello'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            crate::secure_files::harden_existing_file(&path).unwrap();
            let principal = current_principal().unwrap();
            let sid = principal.strip_prefix("windows-sid:").unwrap();
            set_windows_security(&path, &format!("O:{sid}"), true);
        }
        assert!(read_private_catalog(&path).unwrap().contains("hello"));

        fs::write(&path, vec![b'x'; MAX_CATALOG_BYTES as usize + 1]).unwrap();
        assert_eq!(read_private_catalog(&path), Err(INVALID_CATALOG));

        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert_eq!(read_private_catalog(&path), Err(INVALID_CATALOG));

        fs::write(&path, []).unwrap();
        assert_eq!(read_private_catalog(&path), Err(INVALID_CATALOG));
        fs::remove_file(&path).unwrap();
        assert_eq!(read_private_catalog(&path), Err(INVALID_CATALOG));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_catalog() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("operations.toml");
        fs::write(&path, "safe").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(read_private_catalog(&path), Err(INVALID_CATALOG));
    }

    #[cfg(windows)]
    fn set_windows_security(path: &Path, sddl: &str, set_owner: bool) {
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SetFileSecurityW,
        };

        let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let information = if set_owner {
            OWNER_SECURITY_INFORMATION
        } else {
            DACL_SECURITY_INFORMATION
        };
        let applied = unsafe { SetFileSecurityW(wide_path.as_ptr(), information, descriptor) };
        unsafe { LocalFree(descriptor.cast()) };
        assert_ne!(applied, 0);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_broad_and_null_windows_dacls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("operations.toml");
        fs::write(&path, "safe").unwrap();
        set_windows_security(&path, "D:P(A;;FA;;;WD)", false);
        assert_eq!(read_private_catalog(&path), Err(INVALID_CATALOG));
        set_windows_security(&path, "D:NO_ACCESS_CONTROL", false);
        assert_eq!(read_private_catalog(&path), Err(INVALID_CATALOG));
    }

    #[test]
    fn rejects_directory_and_link() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        assert_eq!(read_private_catalog(&dir_path), Err(INVALID_CATALOG));
        let path = dir_path.join("operations.toml");
        fs::write(&path, "safe").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            symlink(&path, dir_path.join("link")).unwrap();
            assert_eq!(
                read_private_catalog(&dir_path.join("link")),
                Err(INVALID_CATALOG)
            );
            symlink(&dir_path, dir_path.join("linked-parent")).unwrap();
            assert_eq!(
                read_private_catalog(&dir_path.join("linked-parent/operations.toml")),
                Err(INVALID_CATALOG)
            );
        }
    }
}
