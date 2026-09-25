//! Not a credential CLI. stdout is reserved for framed browser-native messages.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if wispkey::browser_host::run().is_err() {
        // Input and decrypted payloads must never appear in diagnostics.
        std::process::exit(1);
    }
}
