#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(unix)]
fn script(name: &str) -> PathBuf {
    repo_root().join("scripts").join(name)
}

#[cfg(unix)]
fn run_script(name: &str, args: &[&str]) -> std::process::Output {
    Command::new("bash")
        .arg(script(name))
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run {name}: {error}"))
}

#[cfg(unix)]
fn assert_success(name: &str, output: &std::process::Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{name} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn pinned_action_uses(workflow: &str) -> Vec<(usize, String)> {
    let mut uses = Vec::new();
    for (index, line) in workflow.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("uses:") {
            uses.push((index + 1, rest.trim().to_string()));
        }
    }
    uses
}

fn assert_actions_are_sha_pinned(path: &str, workflow: &str) {
    let uses = pinned_action_uses(workflow);
    assert!(
        !uses.is_empty(),
        "{path} must declare at least one GitHub Action"
    );

    for (line, spec) in uses {
        if spec.starts_with("./") {
            continue;
        }
        let action = spec.split_whitespace().next().expect("uses spec");
        let Some((_, reference)) = action.rsplit_once('@') else {
            panic!("{path}:{line} action is missing a ref: {spec}");
        };
        assert!(
            reference.len() == 40 && reference.chars().all(|ch| ch.is_ascii_hexdigit()),
            "{path}:{line} must pin {action} to a 40-character commit SHA, got {reference}"
        );
    }
}

#[test]
fn release_and_ci_workflows_pin_actions_to_commit_shas() {
    let release = include_str!("../.github/workflows/release.yml");
    let ci = include_str!("../.github/workflows/ci.yml");
    assert_actions_are_sha_pinned(".github/workflows/release.yml", release);
    assert_actions_are_sha_pinned(".github/workflows/ci.yml", ci);
}

#[test]
fn release_publication_has_preflight_and_registry_install_acceptance() {
    let source = include_str!("../.github/workflows/release.yml").replace("\r\n", "\n");
    for line_endings in [&source, &source.replace('\n', "\r\n")] {
        let release = line_endings.replace("\r\n", "\n");
        let preflight = release
            .find("  publication-preflight:\n")
            .expect("publication preflight job");
        let publish_github = release
            .find("  publish-github:\n")
            .expect("GitHub publication job");
        assert!(preflight < publish_github);

        let preflight_block = &release[preflight..publish_github];
        assert!(preflight_block.contains("needs: [verify, provenance]"));
        assert!(preflight_block.contains(
        "startsWith(github.ref, 'refs/tags/v') && (github.event_name == 'push' || inputs.dry_run == false)"
    ));
        assert!(
            preflight_block.contains("CARGO_REGISTRY_TOKEN is required before release publication")
        );
        assert!(release.contains("needs: [verify, provenance, publication-preflight]"));
        assert!(release.contains("needs: [verify, homebrew-release, publication-preflight]"));
        assert!(release.contains("brew tap-new --no-git \"$tap_name\""));
        assert!(release.contains("tap_dir=\"$(brew --repository \"$tap_name\")\""));
        assert!(release.contains("brew install --formula \"$tap_name/wispkey\""));
        assert!(release.contains("brew untap \"$tap_name\""));
        assert!(release.contains("curl --fail --location --silent --show-error \"$formula_url\""));
        assert!(!release.contains("brew install --formula \"$formula_url\""));

        let cargo_install = release
            .find("  cargo-install:\n")
            .expect("Cargo registry install acceptance job");
        let publish_crates = release
            .find("  publish-crates:\n")
            .expect("crates.io publication job");
        assert!(publish_crates < cargo_install);
        let publish_crates_block = &release[publish_crates..cargo_install];
        assert!(!publish_crates_block.contains("is required to publish to crates.io"));
        let cargo_install_block = &release[cargo_install..];
        assert!(cargo_install_block.contains("needs: [verify, publish-crates]"));
        assert!(cargo_install_block.contains("cargo install wispkey"));
        assert!(cargo_install_block.contains("--version \"${VERSION}\""));
        assert!(cargo_install_block.contains("--locked"));
        assert!(cargo_install_block.contains("--root \"$install_root\""));
        assert_eq!(release.matches("brew test wispkey").count(), 2);
    }
}

#[test]
fn install_docs_verify_selected_macos_checksum_entry() {
    let docs = include_str!("../docs/install.md");
    let readme = include_str!("../README.md");
    assert!(docs.contains(
        "Homebrew's current formula loader does not accept arbitrary remote formula URLs"
    ));
    assert!(docs.contains("brew tap-new --no-git \"$tap_name\""));
    assert!(docs.contains("curl --fail --location --silent --show-error \"$formula_url\""));
    assert!(docs.contains("brew install --formula \"$tap_name/wispkey\""));
    assert!(!docs.contains("brew install --formula https://github.com/"));
    assert!(!readme.contains("brew install --formula https://github.com/"));
    assert!(docs.contains("archive=\"wispkey-aarch64-apple-darwin.tar.gz\""));
    assert!(docs.contains("awk -v file=\"$archive\""));
    assert!(docs.contains("missing or duplicate checksum entry for $archive"));
    assert!(docs.contains("shasum -a 256 -c -"));
    assert!(!docs.contains("shasum -a 256 -c SHA256SUMS.txt"));
    assert!(docs.contains("External publication is sequential, not atomic"));
    assert!(docs.contains("Re-run failed jobs"));
}

#[test]
fn homebrew_template_has_required_placeholders() {
    let template = include_str!("../packaging/homebrew/wispkey.rb.tmpl");
    for placeholder in [
        "{{VERSION}}",
        "{{BASE_URL}}",
        "{{SHA_AARCH64_APPLE_DARWIN}}",
        "{{SHA_X86_64_APPLE_DARWIN}}",
        "{{SHA_AARCH64_UNKNOWN_LINUX_GNU}}",
        "{{SHA_X86_64_UNKNOWN_LINUX_GNU}}",
    ] {
        assert!(
            template.contains(placeholder),
            "Homebrew template missing {placeholder}"
        );
    }
    assert!(template.contains("Apache-2.0"));
    assert!(template.contains("bin.install \"wispkey\""));
    assert!(template.contains("doc.install \"LICENSE\""));
    assert!(template.contains("doc.install \"VERSION\""));
    assert!(template.contains("wispkey --version"));
}

#[cfg(unix)]
#[test]
fn package_checksum_and_formula_scripts_produce_verifiable_assets() {
    let root = repo_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin_dir = tmp.path().join("bin");
    let out_dir = tmp.path().join("dist");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    fs::create_dir_all(&out_dir).expect("out dir");

    let binary = bin_dir.join("wispkey");
    fs::write(&binary, b"#!/bin/sh\necho wispkey 0.4.0\n").expect("fake binary");

    let commit = "0123456789abcdef0123456789abcdef01234567";
    let package = run_script(
        "package-release-asset.sh",
        &[
            "--target",
            "aarch64-apple-darwin",
            "--binary",
            binary.to_str().unwrap(),
            "--version",
            "0.4.0",
            "--commit",
            commit,
            "--license",
            root.join("LICENSE").to_str().unwrap(),
            "--readme",
            root.join("README.md").to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
    );
    assert_success("package-release-asset.sh", &package);

    let archive = out_dir.join("wispkey-aarch64-apple-darwin.tar.gz");
    assert!(archive.is_file(), "expected {}", archive.display());

    let extract_dir = tmp.path().join("extract");
    fs::create_dir_all(&extract_dir).expect("extract dir");
    let untar = Command::new("tar")
        .args(["xzf", archive.to_str().unwrap(), "-C"])
        .arg(&extract_dir)
        .output()
        .expect("tar");
    assert_success("tar", &untar);

    assert!(extract_dir.join("wispkey").is_file());
    assert!(extract_dir.join("LICENSE").is_file());
    assert!(extract_dir.join("README.md").is_file());
    let version = fs::read_to_string(extract_dir.join("VERSION")).expect("VERSION");
    assert!(version.contains("version: 0.4.0"));
    assert!(version.contains(&format!("commit: {commit}")));
    assert!(version.contains("license: Apache-2.0"));

    let linux_archive = out_dir.join("wispkey-x86_64-unknown-linux-gnu.tar.gz");
    fs::copy(&archive, &linux_archive).expect("copy linux archive");
    let darwin_x64 = out_dir.join("wispkey-x86_64-apple-darwin.tar.gz");
    fs::copy(&archive, &darwin_x64).expect("copy darwin x64 archive");
    let linux_arm = out_dir.join("wispkey-aarch64-unknown-linux-gnu.tar.gz");
    fs::copy(&archive, &linux_arm).expect("copy linux arm archive");

    let checksums = tmp.path().join("SHA256SUMS.txt");
    let sums = run_script(
        "sha256sums.sh",
        &[
            "--dir",
            out_dir.to_str().unwrap(),
            "--out",
            checksums.to_str().unwrap(),
        ],
    );
    assert_success("sha256sums.sh", &sums);

    let verify = Command::new("sha256sum")
        .args(["-c", checksums.to_str().unwrap()])
        .current_dir(&out_dir)
        .output()
        .or_else(|_| {
            Command::new("shasum")
                .args(["-a", "256", "-c", checksums.to_str().unwrap()])
                .current_dir(&out_dir)
                .output()
        })
        .expect("checksum verify");
    assert_success("checksum verify", &verify);

    let digest_for = |name: &str| -> String {
        fs::read_to_string(&checksums)
            .expect("checksums")
            .lines()
            .find_map(|line| {
                line.rsplit_once("  ")
                    .filter(|(_, file)| *file == name)
                    .map(|(digest, _)| digest.to_string())
            })
            .unwrap_or_else(|| panic!("missing checksum for {name}"))
    };

    let formula_out = tmp.path().join("wispkey.rb");
    let formula = run_script(
        "generate-homebrew-formula.sh",
        &[
            "--version",
            "0.4.0",
            "--base-url",
            "https://github.com/rankupgames/wispkey/releases/download/v0.4.0",
            "--out",
            formula_out.to_str().unwrap(),
            "--sha-aarch64-apple-darwin",
            &digest_for("wispkey-aarch64-apple-darwin.tar.gz"),
            "--sha-x86_64-apple-darwin",
            &digest_for("wispkey-x86_64-apple-darwin.tar.gz"),
            "--sha-aarch64-unknown-linux-gnu",
            &digest_for("wispkey-aarch64-unknown-linux-gnu.tar.gz"),
            "--sha-x86_64-unknown-linux-gnu",
            &digest_for("wispkey-x86_64-unknown-linux-gnu.tar.gz"),
        ],
    );
    assert_success("generate-homebrew-formula.sh", &formula);

    let formula_text = fs::read_to_string(&formula_out).expect("formula");
    assert!(formula_text.contains("version \"0.4.0\""));
    assert!(formula_text.contains("license \"Apache-2.0\""));
    assert!(
        formula_text.contains(
            "https://github.com/rankupgames/wispkey/releases/download/v0.4.0/wispkey-aarch64-apple-darwin.tar.gz"
        )
    );
    assert!(!formula_text.contains("{{"));
}

#[cfg(unix)]
#[test]
fn packaging_scripts_fail_closed_on_invalid_input() {
    let root = repo_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let binary = tmp.path().join("wispkey");
    fs::write(&binary, b"fake").expect("binary");

    let missing_binary = run_script(
        "package-release-asset.sh",
        &[
            "--target",
            "x86_64-unknown-linux-gnu",
            "--binary",
            tmp.path().join("missing").to_str().unwrap(),
            "--version",
            "0.4.0",
            "--commit",
            "0123456789abcdef0123456789abcdef01234567",
            "--license",
            root.join("LICENSE").to_str().unwrap(),
            "--readme",
            root.join("README.md").to_str().unwrap(),
            "--out-dir",
            tmp.path().to_str().unwrap(),
        ],
    );
    assert!(!missing_binary.status.success());

    let bad_commit = run_script(
        "package-release-asset.sh",
        &[
            "--target",
            "x86_64-unknown-linux-gnu",
            "--binary",
            binary.to_str().unwrap(),
            "--version",
            "0.4.0",
            "--commit",
            "not-a-sha",
            "--license",
            root.join("LICENSE").to_str().unwrap(),
            "--readme",
            root.join("README.md").to_str().unwrap(),
            "--out-dir",
            tmp.path().to_str().unwrap(),
        ],
    );
    assert!(!bad_commit.status.success());

    let bad_digest = run_script(
        "generate-homebrew-formula.sh",
        &[
            "--version",
            "0.4.0",
            "--base-url",
            "https://example.invalid",
            "--out",
            tmp.path().join("wispkey.rb").to_str().unwrap(),
            "--sha-aarch64-apple-darwin",
            "abc",
            "--sha-x86_64-apple-darwin",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--sha-aarch64-unknown-linux-gnu",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--sha-x86_64-unknown-linux-gnu",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ],
    );
    assert!(!bad_digest.status.success());

    let empty_dir = tmp.path().join("empty");
    fs::create_dir_all(&empty_dir).expect("empty dir");
    let empty_sums = run_script(
        "sha256sums.sh",
        &[
            "--dir",
            empty_dir.to_str().unwrap(),
            "--out",
            tmp.path().join("SHA256SUMS.txt").to_str().unwrap(),
        ],
    );
    assert!(!empty_sums.status.success());
}
