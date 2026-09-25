mod common;

use common::*;
use serde_json::Value;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Stdio;
use std::time::Duration;
use uuid::Uuid;

const CANARY: &str = "synthetic-operation-auth-canary";
const SPOOFED_REQUESTER: &str = "forged-requester-label";

fn assert_private_output(output: &std::process::Output, forbidden: &[&str]) {
    for value in forbidden {
        assert!(
            !output
                .stdout
                .windows(value.len())
                .any(|chunk| chunk == value.as_bytes())
        );
        assert!(
            !output
                .stderr
                .windows(value.len())
                .any(|chunk| chunk == value.as_bytes())
        );
    }
}

fn request(port: u16, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: 0\r\n").unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    write!(stream, "\r\n").unwrap();
    stream.flush().unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("HTTP status");
    (status, raw)
}

fn assert_safe_response(response: &(u16, String), forbidden: &[&str]) {
    for value in forbidden {
        assert!(!response.1.contains(value));
    }
    let body = response.1.split_once("\r\n\r\n").expect("HTTP body").1;
    let json: Value = serde_json::from_str(body).expect("JSON error response");
    assert!(json.get("error").and_then(Value::as_str).is_some());
    assert_eq!(json.as_object().unwrap().len(), 1);
}

#[test]
fn noninteractive_approval_never_issues_grant_even_with_password_env() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let db_path = dir.path().join("vault.db");
    let before: i64 = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM operation_grants", [], |row| {
            row.get(0)
        })
        .unwrap();
    for format in [None, Some("json")] {
        let mut command = wispkey_bin();
        if let Some(format) = format {
            command.args(["--format", format]);
        }
        let output = command
            .args(["operation", "authorize", CANARY])
            .env("WISPKEY_VAULT_PATH", dir.path())
            .env("WISPKEY_PASSWORD", "test-password")
            .env("WISPKEY_REQUESTER", SPOOFED_REQUESTER)
            .env("RUST_LOG", "trace")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_private_output(&output, &["test-password", CANARY, SPOOFED_REQUESTER]);
        if format.is_some() {
            let value: Value = serde_json::from_slice(&output.stdout).expect("JSON failure");
            assert_eq!(value["execution_available"], false);
            assert!(
                value["error"]
                    .as_str()
                    .unwrap()
                    .contains("interactive terminal")
            );
        } else {
            assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
        }
    }
    let after: i64 = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM operation_grants", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn operation_api_rejects_management_token_forgery_and_unknown_references() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let added = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "add",
            "operation-canary",
            "--type",
            "api_key",
            "--value",
            CANARY,
            "--hosts",
            "example.invalid",
        ],
    );
    let token = added["credential"]["wisp_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let enrolled = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "operation-worker",
            "--credential",
            "operation-canary",
        ],
    );
    let instance_id = enrolled["id"].as_str().unwrap().to_owned();
    let instance_secret = enrolled["secret"].as_str().unwrap().to_owned();

    let stderr_path = dir.path().join("proxy-stderr.log");
    let stderr_file = File::create(&stderr_path).unwrap();
    let child = wispkey_bin()
        .args(["serve", "--random-port", "--require-identity"])
        .env("WISPKEY_VAULT_PATH", dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .env("RUST_LOG", "trace")
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .unwrap();
    let proxy = ChildGuard(child);
    let info = wait_for_proxy_info(dir.path());
    let port = info["port"].as_u64().unwrap() as u16;
    let management = info["management_token"].as_str().unwrap().to_owned();
    let unknown = Uuid::new_v4().to_string();
    let route = format!("/api/operations/grants/{unknown}");
    let forbidden = [
        CANARY,
        token.as_str(),
        management.as_str(),
        instance_secret.as_str(),
        SPOOFED_REQUESTER,
    ];

    let management_only = request(
        port,
        "GET",
        &route,
        &[
            ("x-wispkey-management-token", &management),
            ("x-wispkey-requester", SPOOFED_REQUESTER),
        ],
    );
    assert_eq!(management_only.0, 401);
    assert_safe_response(&management_only, &forbidden);
    let bearer_only = request(
        port,
        "GET",
        &route,
        &[("authorization", &format!("Bearer {management}"))],
    );
    assert_eq!(bearer_only.0, 401);
    assert_safe_response(&bearer_only, &forbidden);
    let missing = request(port, "GET", &route, &[]);
    assert_eq!(missing.0, 401);
    assert_safe_response(&missing, &forbidden);
    let forged = request(
        port,
        "GET",
        &route,
        &[
            ("x-wispkey-instance-id", &instance_id),
            ("x-wispkey-instance-secret", "forged-secret"),
            ("x-wispkey-requester", SPOOFED_REQUESTER),
        ],
    );
    assert_eq!(forged.0, 401);
    assert_safe_response(&forged, &forbidden);
    let valid_identity = [
        ("x-wispkey-instance-id", instance_id.as_str()),
        ("x-wispkey-instance-secret", instance_secret.as_str()),
        ("x-wispkey-requester", SPOOFED_REQUESTER),
    ];
    let absent = request(port, "GET", &route, &valid_identity);
    assert_eq!(absent.0, 403);
    assert_safe_response(&absent, &forbidden);
    let invalid = request(
        port,
        "GET",
        &format!("/api/operations/grants/{CANARY}"),
        &valid_identity,
    );
    assert_eq!(invalid.0, 404);
    assert_safe_response(&invalid, &forbidden);
    let execute = request(port, "POST", &format!("{route}/execute"), &valid_identity);
    assert_eq!(execute.0, 403);
    assert_safe_response(&execute, &forbidden);

    let db = rusqlite::Connection::open(dir.path().join("vault.db")).unwrap();
    let mut statement = db.prepare("SELECT requester FROM operation_audit").unwrap();
    let requesters: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(requesters.iter().all(|value| value != SPOOFED_REQUESTER));
    assert!(
        requesters
            .iter()
            .all(|value| value == "identity_missing" || value == &instance_id)
    );
    drop(statement);
    drop(db);
    drop(proxy);
    let stderr = std::fs::read_to_string(stderr_path).unwrap();
    for value in forbidden {
        assert!(!stderr.contains(value));
    }
}
