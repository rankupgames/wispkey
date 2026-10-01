fn main() {
    println!("cargo:rerun-if-changed=src/browser_host/macos.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/browser_host/macos.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .warnings_into_errors(true)
            .compile("wispkey_macos_consent");
        println!("cargo:rustc-link-lib=framework=AppKit");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }
}
