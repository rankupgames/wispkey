use crate::core::browser::{FillRequest, Result};

#[cfg(not(windows))]
pub(super) fn verify(_: &FillRequest) -> Result<bool> {
    Err("browser fill requires Windows Hello; this platform has no approval backend yet")
}

#[cfg(windows)]
pub(super) fn verify(request: &FillRequest) -> Result<bool> {
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
    use windows::Win32::System::WinRT::{
        IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CW_USEDEFAULT, CreateWindowExW, DestroyWindow, DispatchMessageW, IsWindow, MSG, PM_REMOVE,
        PeekMessageW, SetForegroundWindow, TranslateMessage, WINDOW_EX_STYLE, WS_CHILD,
        WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };
    use windows::core::{HSTRING, PCWSTR, factory, w};

    // An ordinary "Approve" button can be clicked by automation. Verification
    // instead requires the user's OS PIN/biometric; there is no bypass setting.
    let result = (|| -> windows::core::Result<bool> {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED)?;
        }
        struct Apartment;
        impl Drop for Apartment {
            fn drop(&mut self) {
                unsafe {
                    RoUninitialize();
                }
            }
        }
        let _apartment = Apartment;
        let window = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                w!("WispKey browser fill"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                680,
                520,
                None,
                None,
                None,
                None,
            )?
        };
        struct Window(windows::Win32::Foundation::HWND);
        impl Drop for Window {
            fn drop(&mut self) {
                unsafe {
                    let _ = DestroyWindow(self.0);
                }
            }
        }
        let window = Window(window);
        let prompt = HSTRING::from(format!(
            "Fill only at {}\nLogin: {} / {}\nAgent label (unverified): {}\nReason (unverified): {}",
            request.origin, request.project, request.name, request.requester, request.reason,
        ));
        unsafe {
            // Display full metadata separately from the potentially compact OS
            // prompt. This window has no approval button or credential input.
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                PCWSTR(prompt.as_ptr()),
                WS_CHILD | WS_VISIBLE,
                20,
                20,
                620,
                440,
                Some(window.0),
                None,
                None,
                None,
            )?;
            let _ = SetForegroundWindow(window.0);
        }
        let verifier = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
        let operation: windows_future::IAsyncOperation<UserConsentVerificationResult> =
            unsafe { verifier.RequestVerificationForWindowAsync(window.0, &prompt)? };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(110);
        while operation.Status()? == windows_future::AsyncStatus::Started {
            let mut message = MSG::default();
            unsafe {
                while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            if std::time::Instant::now() >= deadline
                || !unsafe { IsWindow(Some(window.0)) }.as_bool()
            {
                operation.Cancel()?;
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        Ok(operation.GetResults()? == UserConsentVerificationResult::Verified)
    })();
    result.map_err(|_| "Windows Hello approval unavailable; fill refused")
}
