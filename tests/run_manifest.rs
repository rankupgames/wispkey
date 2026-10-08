mod common;

use common::*;

#[test]
fn run_manifest_parse_errors_do_not_disclose_values_or_start_the_child() {
    const PRIVATE_VALUE: &str = "synthetic-manifest-private-value";
    let fixtures = [
        format!("[env]\nTOKEN = \"{PRIVATE_VALUE}\" trailing\n"),
        format!("[env]\nTOKEN = \"{PRIVATE_VALUE}\\q\"\n"),
    ];
    for fixture in fixtures {
        let vault_dir = tempfile::tempdir().expect("isolated vault dir");
        let manifest_dir = tempfile::tempdir().expect("manifest dir");
        let manifest = manifest_dir.path().join("wispkey.toml");
        std::fs::write(&manifest, fixture).expect("write malformed manifest");
        let manifest_arg = manifest.to_string_lossy();
        let output = run_wispkey(
            vault_dir.path(),
            &[
                "run",
                "--manifest",
                &manifest_arg,
                "--",
                env!("CARGO_BIN_EXE_wispkey"),
                "--version",
            ],
        );
        assert!(!output.status.success());
        assert!(output.stdout.is_empty(), "child must not run");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("failed to parse manifest"));
        assert!(
            !stderr.contains(PRIVATE_VALUE),
            "manifest values must not enter CLI diagnostics"
        );
        assert!(!vault_dir.path().join("vault.db").exists());
    }
}
