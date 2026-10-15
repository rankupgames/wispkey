#![cfg(unix)]
mod common;
use common::*;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const SECRET: &str = "synthetic-worktree-secret-one";
const MANIFEST: &str = r#"[env]
APP_SECRET = "cred:development-secret"
PORT = "3000"
BROWSER_ORIGIN = "http://localhost:3000"
DATABASE_URL = "file:./local.db"
[worktree]
overrides = ["PORT", "BROWSER_ORIGIN", "DATABASE_URL"]
"#;

struct Fixture {
    dir: tempfile::TempDir,
    vault: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().unwrap(),
            vault: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(fixture.repo()).unwrap();
        git(&fixture.repo(), &["init", "-b", "main"]);
        git(
            &fixture.repo(),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "fixture",
            ],
        );
        git(
            &fixture.repo(),
            &[
                "worktree",
                "add",
                "-b",
                "feature",
                fixture.worktree().to_str().unwrap(),
            ],
        );
        init_vault(fixture.vault.path());
        assert_ok(run_wispkey(
            fixture.vault.path(),
            &["partition", "create", "development", "--project", "default"],
        ));
        assert_ok(run_wispkey(
            fixture.vault.path(),
            &[
                "add",
                "development-secret",
                "--type",
                "api_key",
                "--value",
                SECRET,
                "--hosts",
                "api.example.com",
                "--partition",
                "development",
                "--project",
                "default",
            ],
        ));
        fs::write(fixture.repo().join("wispkey.toml"), MANIFEST).unwrap();
        fixture
    }
    fn repo(&self) -> std::path::PathBuf {
        self.dir.path().join("main")
    }
    fn worktree(&self) -> std::path::PathBuf {
        self.dir.path().join("feature")
    }
    fn command(&self, cwd: &Path) -> Command {
        let mut command = wispkey_bin();
        command
            .current_dir(cwd)
            .env("WISPKEY_VAULT_PATH", self.vault.path())
            .env("WISPKEY_PASSWORD", "test-password")
            .env("WISPKEY_PROTECTOR", "file")
            .env_remove("WISPKEY_PROJECT");
        command
    }
    fn run(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command(cwd).args(args).output().unwrap()
    }
    fn bind(&self) -> Output {
        self.run(
            &self.repo(),
            &[
                "env",
                "bind",
                "--project",
                "default",
                "--environment",
                "development",
                "--manifest",
                "wispkey.toml",
            ],
        )
    }
    fn denied(&self, cwd: &Path, flags: &[&str]) -> Output {
        let mut args = vec!["run"];
        args.extend_from_slice(flags);
        args.extend(["--", "sh", "-c", "touch launched"]);
        let output = self.run(cwd, &args);
        assert!(!output.status.success(), "unexpected success");
        assert!(
            !cwd.join("launched").exists(),
            "child launched on denied configuration"
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
        output
    }
}
fn git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn assert_ok(output: Output) -> Output {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn two_real_worktrees_inherit_fresh_secrets_and_isolated_defaults_without_materialization() {
    let f = Fixture::new();
    assert_ok(f.bind());
    // Changing the source manifest cannot silently expand an approved binding.
    fs::write(f.repo().join("wispkey.toml"), "not valid TOML").unwrap();
    fs::write(
        f.repo().join("wispkey.local.toml"),
        "[env]\nPORT = '3100'\nBROWSER_ORIGIN = 'http://localhost:3100'\n",
    )
    .unwrap();
    fs::write(f.worktree().join("wispkey.local.toml"), "[env]\nPORT = '3200'\nBROWSER_ORIGIN = 'http://localhost:3200'\nDATABASE_URL = 'file:./feature.db'\n").unwrap();
    for (cwd, port, origin, db) in [
        (f.repo(), "3100", "http://localhost:3100", "local.db"),
        (f.worktree(), "3200", "http://localhost:3200", "feature.db"),
    ] {
        let script = "test \"$APP_SECRET\" = \"$1\" && test \"$PORT\" = \"$2\" && test \"$BROWSER_ORIGIN\" = \"$3\" && test \"$DATABASE_URL\" = \"file:./$4\" && touch \"${DATABASE_URL#file:}\"";
        let output = assert_ok(f.run(
            &cwd,
            &[
                "run", "--", "sh", "-c", script, "verify", SECRET, port, origin, db,
            ],
        ));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert!(cwd.join(db).exists());
        assert!(!cwd.join(".env").exists());
        assert!(!cwd.join(".env.local").exists());
    }
    assert!(!f.repo().join("feature.db").exists());
    assert!(!f.worktree().join("local.db").exists());
    // Explicit CLI settings win over worktree settings, then bound defaults.
    assert_ok(f.run(
        &f.worktree(),
        &[
            "run",
            "--env",
            "PORT=3300",
            "--",
            "sh",
            "-c",
            "test \"$PORT\" = 3300",
        ],
    ));
    let mut child = f
        .command(&f.repo())
        .args([
            "replace-value",
            "development-secret",
            "--project",
            "default",
            "--partition",
            "development",
            "--stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic-updated-secret")
        .unwrap();
    assert_ok(child.wait_with_output().unwrap());
    assert_ok(f.run(
        &f.worktree(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            "test \"$APP_SECRET\" = synthetic-updated-secret",
        ],
    ));
    let log = run_wispkey_json(f.vault.path(), &["--format", "json", "log", "--last", "20"]);
    let serialized = log.to_string();
    assert!(serialized.contains("CredentialRun"));
    assert!(!serialized.contains(SECRET));
    assert!(!serialized.contains("synthetic-updated-secret"));
    // Saved bindings contain selectors, never decrypted credential values.
    for file in fs::read_dir(f.vault.path().join("repository-bindings")).unwrap() {
        let raw = fs::read_to_string(file.unwrap().path()).unwrap();
        assert!(!raw.contains(SECRET));
        assert!(!raw.contains("synthetic-updated-secret"));
    }
}

#[test]
fn unrelated_repositories_missing_bindings_and_scope_overrides_fail_before_launch() {
    let f = Fixture::new();
    f.denied(&f.worktree(), &[]);
    assert_ok(f.bind());
    let unrelated = f.dir.path().join("unrelated");
    fs::create_dir(&unrelated).unwrap();
    git(&unrelated, &["init"]);
    fs::write(unrelated.join("wispkey.toml"), MANIFEST).unwrap();
    f.denied(&unrelated, &[]);
    // Environment Git routing cannot make the unrelated repository inherit.
    let output = f
        .command(&unrelated)
        .env("GIT_DIR", f.repo().join(".git"))
        .args(["run", "--", "sh", "-c", "touch launched"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!unrelated.join("launched").exists());
    f.denied(&f.worktree(), &["--project", "other"]);
    for entry in [
        "APP_SECRET=leak",
        "PORT=cred:development-secret",
        "UNDECLARED=value",
        "not-an-assignment",
    ] {
        f.denied(&f.worktree(), &["--env", entry]);
    }
    // Explicit manual manifests remain available, and never require a binding.
    fs::write(unrelated.join("manual.toml"), "[env]\nPORT = '9999'\n").unwrap();
    assert_ok(f.run(
        &unrelated,
        &[
            "run",
            "--manifest",
            "manual.toml",
            "--",
            "sh",
            "-c",
            "test \"$PORT\" = 9999",
        ],
    ));
}

#[test]
fn invalid_local_config_missing_credentials_and_cross_partition_credentials_fail_closed() {
    let f = Fixture::new();
    assert_ok(f.bind());
    let local = f.worktree().join("wispkey.local.toml");
    for content in [
        "[env]\nPORT = 42",
        "[env]\nAPP_SECRET = 'literal'",
        "[env]\nPORT = 'secret-canary'\n[unexpected]",
        "[env]\nPORT = 'unterminated-secret-canary",
    ] {
        fs::write(&local, content).unwrap();
        let output = f.denied(&f.worktree(), &[]);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-canary"));
    }
    fs::remove_file(local).unwrap();
    assert_ok(run_wispkey(
        f.vault.path(),
        &[
            "partition",
            "assign",
            "development-secret",
            "--to",
            "personal",
        ],
    ));
    f.denied(&f.worktree(), &[]);
    assert!(!f.bind().status.success());
    assert_ok(run_wispkey(
        f.vault.path(),
        &["remove", "development-secret"],
    ));
    f.denied(&f.worktree(), &[]);
}

#[test]
fn shared_database_and_production_require_explicit_choices() {
    let f = Fixture::new();
    assert_ok(f.bind());
    for value in [
        "file:/tmp/shared.db",
        "sqlite://shared.db",
        "file:../shared.db",
        "file:%2fshared.db",
        "postgres://localhost/db",
        "cred:development-secret",
    ] {
        f.denied(&f.worktree(), &["--env", &format!("DATABASE_URL={value}")]);
    }
    assert_ok(run_wispkey(
        f.vault.path(),
        &["partition", "create", "production", "--project", "default"],
    ));
    assert!(
        !f.run(
            &f.repo(),
            &[
                "env",
                "bind",
                "--project",
                "default",
                "--environment",
                "production",
                "--manifest",
                "wispkey.toml",
                "--replace"
            ]
        )
        .status
        .success()
    );
    // Rebinding is never implicit.
    assert!(!f.bind().status.success());
    fs::write(
        f.repo().join("wispkey.toml"),
        MANIFEST.replace("[worktree]", "[worktree]\nallow_shared_database = true"),
    )
    .unwrap();
    assert_ok(f.run(
        &f.repo(),
        &[
            "env",
            "bind",
            "--project",
            "default",
            "--environment",
            "development",
            "--manifest",
            "wispkey.toml",
            "--replace",
        ],
    ));
    assert_ok(f.run(
        &f.worktree(),
        &[
            "run",
            "--env",
            "DATABASE_URL=file:/explicit/shared.db",
            "--",
            "sh",
            "-c",
            "test \"$DATABASE_URL\" = file:/explicit/shared.db",
        ],
    ));
}

#[test]
fn nested_directories_and_spoofed_worktree_pointers() {
    let f = Fixture::new();
    assert_ok(f.bind());
    let nested = f.worktree().join("nested");
    fs::create_dir(&nested).unwrap();
    assert_ok(f.run(&nested, &["run", "--", "sh", "-c", "test \"$PORT\" = 3000"]));
    let fake = f.dir.path().join("fake");
    fs::create_dir(&fake).unwrap();
    // Pointing a new folder at the real worktree gitdir does not register it.
    fs::copy(f.worktree().join(".git"), fake.join(".git")).unwrap();
    f.denied(&fake, &[]);
}

#[test]
fn replacing_a_repository_at_the_same_path_does_not_inherit() {
    let f = Fixture::new();
    assert_ok(f.bind());
    fs::rename(f.repo().join(".git"), f.repo().join("original-git")).unwrap();
    git(&f.repo(), &["init"]);
    f.denied(&f.repo(), &[]);
}

#[test]
fn copied_binding_and_git_marker_do_not_authorize_another_repository() {
    let f = Fixture::new();
    assert_ok(f.bind());
    let unrelated = f.dir.path().join("copy");
    fs::create_dir(&unrelated).unwrap();
    git(&unrelated, &["init"]);
    fs::copy(
        f.repo().join(".git/wispkey-repository-id"),
        unrelated.join(".git/wispkey-repository-id"),
    )
    .unwrap();
    f.denied(&unrelated, &[]);
}

#[test]
fn binding_ignores_active_project_and_rejects_nul_values_without_secret_diagnostics() {
    let f = Fixture::new();
    assert_ok(f.bind());
    assert_ok(
        f.command(&f.worktree())
            .env("WISPKEY_PROJECT", "nonexistent")
            .args(["run", "--", "sh", "-c", "test \"$PORT\" = 3000"])
            .output()
            .unwrap(),
    );
    fs::write(
        f.worktree().join("wispkey.local.toml"),
        "[env]\nPORT = \"canary\\u0000\"\n",
    )
    .unwrap();
    let output = f.denied(&f.worktree(), &[]);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("canary"));
}

#[test]
fn revoked_or_expired_credentials_cannot_be_inherited() {
    for expiry in ["non-expiring", "2000-01-01T00:00:00Z"] {
        let f = Fixture::new();
        assert_ok(f.bind());
        assert_ok(run_wispkey(
            f.vault.path(),
            &[
                "auth",
                "register",
                "development-secret",
                "--project",
                "default",
                "--provider",
                "synthetic",
                "--account",
                "test",
                "--origin",
                "https://api.example.com",
                "--provider-expiry",
                expiry,
            ],
        ));
        if expiry == "non-expiring" {
            assert_ok(run_wispkey(
                f.vault.path(),
                &[
                    "auth",
                    "revoke",
                    "development-secret",
                    "--project",
                    "default",
                ],
            ));
        }
        f.denied(&f.worktree(), &[]);
    }
}

#[test]
fn recreated_partition_name_does_not_acquire_old_binding() {
    let f = Fixture::new();
    assert_ok(f.bind());
    assert_ok(run_wispkey(
        f.vault.path(),
        &["partition", "delete", "development"],
    ));
    assert_ok(run_wispkey(
        f.vault.path(),
        &["partition", "create", "development"],
    ));
    assert_ok(run_wispkey(
        f.vault.path(),
        &[
            "partition",
            "assign",
            "development-secret",
            "--to",
            "development",
        ],
    ));
    f.denied(&f.worktree(), &[]);
}

#[test]
fn parent_env_is_overridden_and_cli_last_assignment_wins() {
    let f = Fixture::new();
    assert_ok(f.bind());
    assert_ok(
        f.command(&f.worktree())
            .env("PORT", "untrusted-parent")
            .args([
                "run",
                "--env",
                "PORT=4000",
                "--env",
                "PORT=4001",
                "--",
                "sh",
                "-c",
                "test \"$PORT\" = 4001",
            ])
            .output()
            .unwrap(),
    );
}

#[test]
fn oversized_and_nonregular_configuration_fails_before_launch() {
    let f = Fixture::new();
    assert_ok(f.bind());
    let local = f.worktree().join("wispkey.local.toml");
    fs::write(&local, format!("[env]\nPORT = '{}'", "x".repeat(65536))).unwrap();
    f.denied(&f.worktree(), &[]);
    fs::remove_file(&local).unwrap();
    fs::create_dir(&local).unwrap();
    f.denied(&f.worktree(), &[]);
    fs::remove_dir(&local).unwrap();
    let path = std::ffi::CString::new(local.as_os_str().as_encoded_bytes()).unwrap();
    // A FIFO must be rejected without waiting for a writer.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    f.denied(&f.worktree(), &[]);
}
