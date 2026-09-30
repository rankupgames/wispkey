mod common;
use common::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

const CANARY: &str = "synthetic-auth-release-never-log";
fn register(dir: &Path, expiry: &str) -> String {
    register_at(dir, expiry, "https://127.0.0.1")
}

fn register_at(dir: &Path, expiry: &str, origin: &str) -> String {
    let secret = dir.join("canary.txt");
    write_private_test_file(&secret, CANARY);
    let added = run_wispkey_json(
        dir,
        &[
            "--format",
            "json",
            "add",
            "bounded-key",
            "--type",
            "api_key",
            "--value-file",
            secret.to_str().unwrap(),
            "--hosts",
            "127.0.0.1",
        ],
    );
    let output = run_wispkey(
        dir,
        &[
            "auth",
            "register",
            "bounded-key",
            "--project",
            "default",
            "--provider",
            "fixture",
            "--account",
            "test",
            "--origin",
            origin,
            "--provider-expiry",
            expiry,
            "--use-until",
            "2100-01-01T00:00:00Z",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    added["credential"]["wisp_token"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn proxy(dir: &Path) -> (ChildGuard, u16) {
    let child = wispkey_bin()
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_PROTECTOR", "file")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let info = wait_for_proxy_info(dir);
    (ChildGuard(child), info["port"].as_u64().unwrap() as u16)
}
fn send(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn expired_and_revoked_tokens_are_denied_at_header_body_and_query_release() {
    for expiry in ["2000-01-01T00:00:00Z", "non-expiring"] {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let token = register_at(
            dir.path(),
            expiry,
            &format!("https://127.0.0.1:{upstream_port}"),
        );
        if expiry == "non-expiring" {
            assert!(
                run_wispkey(
                    dir.path(),
                    &["auth", "revoke", "bounded-key", "--project", "default"]
                )
                .status
                .success()
            );
        }

        let (_guard, port) = proxy(dir.path());
        let requests = [
            format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-Target-Url: https://127.0.0.1:{upstream_port}/\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
            ),
            format!(
                "POST https://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{token}",
                token.len()
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-Target-Url: https://127.0.0.1:{upstream_port}/?key={token}\r\nConnection: close\r\n\r\n"
            ),
        ];
        for request in requests {
            let response = send(port, &request);
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
            assert!(!response.contains(CANARY));
            assert!(!response.contains(&token));
            assert!(
                upstream.accept().is_err(),
                "denied request must not connect upstream"
            );
        }
        let logs = run_wispkey(dir.path(), &["--format", "json", "log"]);
        assert!(!String::from_utf8_lossy(&logs.stdout).contains(CANARY));
        assert!(!String::from_utf8_lossy(&logs.stdout).contains(&token));
    }
}

#[test]
fn registered_token_denies_http_and_wrong_https_port_before_upstream_connection() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let token = register(dir.path(), "non-expiring");
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let (_guard, port) = proxy(dir.path());
    for scheme in ["http", "https"] {
        let response = send(
            port,
            &format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-Target-Url: {scheme}://127.0.0.1:{upstream_port}/\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(upstream.accept().is_err());
        assert!(!response.contains(CANARY));
    }
}

#[test]
fn expired_auth_cannot_escape_through_exec_run_or_inject() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    register(dir.path(), "2000-01-01T00:00:00Z");
    let template = dir.path().join("template.txt");
    std::fs::write(&template, "{{ cred:bounded-key }}").unwrap();
    let output_file = dir.path().join("rendered.txt");
    let manifest = dir.path().join("wispkey.toml");
    std::fs::write(&manifest, "[env]\nTEST_SECRET = \"cred:bounded-key\"\n").unwrap();
    let binary = env!("CARGO_BIN_EXE_wispkey");
    for args in [
        vec![
            "exec",
            "--credential",
            "bounded-key",
            "--env",
            "TEST_SECRET",
            "--",
            binary,
            "--version",
        ],
        vec![
            "run",
            "--manifest",
            manifest.to_str().unwrap(),
            "--",
            binary,
            "--version",
        ],
        vec![
            "inject",
            "-i",
            template.to_str().unwrap(),
            "-o",
            output_file.to_str().unwrap(),
        ],
    ] {
        let output = run_wispkey(dir.path(), &args);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("wispkey 0."),
            "child must not launch"
        );
    }
    assert!(!output_file.exists());
}

#[test]
fn malformed_registered_row_never_falls_back_to_colliding_sideload() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    register(dir.path(), "non-expiring");
    let token = "wk_env_auth_canary";
    let db = rusqlite::Connection::open(dir.path().join("vault.db")).unwrap();
    db.execute(
        "UPDATE credentials SET wisp_token=?1,credential_type='malformed' WHERE name='bounded-key'",
        [token],
    )
    .unwrap();
    let child = wispkey_bin()
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_PROTECTOR", "file")
        .env(
            "WISPKEY_SIDELOAD_AUTH_CANARY",
            "synthetic-sideload-do-not-fallback",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);
    let info = wait_for_proxy_info(dir.path());
    let port = info["port"].as_u64().unwrap() as u16;
    let response = send(
        port,
        &format!(
            "GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(!response.contains(CANARY));
    assert!(!response.contains("synthetic-sideload-do-not-fallback"));
    assert!(!response.contains(token));
}
