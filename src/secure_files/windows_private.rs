//! Shared read-only Windows owner and conservative ACL verification.
const INVALID_CATALOG: &str = "private file protection is unavailable or unsafe";
use std::ffi::c_void;
use std::fs::File;
use std::mem::{align_of, size_of};
use std::os::windows::io::AsRawHandle;
use std::ptr::{NonNull, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, IsValidAcl,
    IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct Local<T>(*mut T);
impl<T> Drop for Local<T> {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0.cast()) };
    }
}

fn current_sid() -> Result<(Vec<usize>, PSID), &'static str> {
    let mut raw_token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err("local OS principal is unavailable");
    }
    let token = Token(raw_token);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
        return Err("local OS principal is unavailable");
    }
    // usize storage gives TOKEN_USER its required pointer alignment.
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err("local OS principal is unavailable");
    }
    debug_assert!(align_of::<usize>() >= align_of::<TOKEN_USER>());
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err("local OS principal is unavailable");
    }
    Ok((buffer, sid))
}

pub(crate) fn current_sid_string() -> Result<String, &'static str> {
    let (_buffer, sid) = current_sid()?;
    let mut wide = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err("local OS principal is unavailable");
    }
    let wide = Local(wide);
    let mut length = 0;
    while length < 256 && unsafe { *wide.0.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err("local OS principal is unavailable");
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(wide.0, length) })
        .map_err(|_| "local OS principal is unavailable")
}

fn well_known_sid(value: &str) -> Result<Local<c_void>, &'static str> {
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid = null_mut();
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
        return Err(INVALID_CATALOG);
    }
    Ok(Local(sid))
}

pub(crate) fn verify_acl(file: &File) -> Result<(), &'static str> {
    let (_sid_buffer, user_sid) = current_sid().map_err(|_| INVALID_CATALOG)?;
    let system = well_known_sid("S-1-5-18")?;
    let administrators = well_known_sid("S-1-5-32-544")?;
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(INVALID_CATALOG);
    }
    let _descriptor = Local(descriptor);
    let mut actual_owner = null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut actual_owner, &mut owner_defaulted) }
        == 0
        || actual_owner.is_null()
        || unsafe { IsValidSid(actual_owner) } == 0
        || unsafe { EqualSid(actual_owner, user_sid) } == 0
    {
        return Err(INVALID_CATALOG);
    }
    let mut present = 0;
    let mut actual_dacl = null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut present,
            &mut actual_dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || present == 0
        || actual_dacl.is_null()
        || unsafe { IsValidAcl(actual_dacl) } == 0
        || actual_dacl != dacl
    {
        return Err(INVALID_CATALOG);
    }
    // Unknown ACE types fail closed. Deny ACEs grant nothing and are safe.
    // Inherit-only grants do not apply to this file, but still require a
    // trusted SID to keep this policy simple and conservative.
    for index in 0..unsafe { (*actual_dacl).AceCount } {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(actual_dacl, index as u32, &mut ace) } == 0
            || NonNull::new(ace).is_none()
        {
            return Err(INVALID_CATALOG);
        }
        let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
        if header.AceType == 1 {
            continue; // ACCESS_DENIED_ACE_TYPE
        }
        if header.AceType != 0 || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(INVALID_CATALOG);
        }
        let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
        let sid_bytes = header.AceSize as usize - 8; // ACE header + access mask
        let sid_start = (&allowed.SidStart as *const u32).cast::<u8>();
        let subauthorities = unsafe { *sid_start.add(1) } as usize;
        if subauthorities > 15 || 8 + 4 * subauthorities > sid_bytes {
            return Err(INVALID_CATALOG);
        }
        let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
        if unsafe { IsValidSid(sid) } == 0
            || ![user_sid, system.0, administrators.0]
                .iter()
                .any(|trusted| unsafe { EqualSid(*trusted, sid) } != 0)
        {
            return Err(INVALID_CATALOG);
        }
    }
    Ok(())
}
