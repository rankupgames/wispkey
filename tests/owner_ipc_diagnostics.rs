#[path = "common/owner_ipc_capture.rs"]
mod capture;

use capture::{MAX_LINE_BYTES, MAX_RECORDS, PhaseCapture};

fn record(sequence: usize) -> String {
    format!(
        "WKIPC_PHASE v1 pid=42 seq={sequence} method=generate_login phase=handler_start elapsed_ms=123\n"
    )
}

#[test]
fn failure_capture_excludes_private_values_unknown_labels_and_foreign_processes() {
    let mut capture = PhaseCapture::new(42);
    let valid = record(1);
    for rejected in [
        "raw password=secret-canary request=private-label\n".to_string(),
        valid.replace("generate_login", "secret-canary"),
        valid.replace("handler_start", "private-label"),
        valid.replace("pid=42", "pid=43"),
        valid.replace("elapsed_ms=123", "elapsed_ms=secret-canary"),
        valid.replace('\n', " value=secret-canary\n"),
    ] {
        capture.feed(rejected.as_bytes());
    }
    capture.feed(valid.as_bytes());
    let (accepted, output) = capture.snapshot_since(0);
    assert_eq!(accepted, 1);
    assert_eq!(output, valid);
    assert!(!output.contains("secret-canary"));
    assert!(!output.contains("private-label"));
}

#[test]
fn capture_keeps_a_bounded_tail_and_reports_only_newly_drained_events() {
    let mut capture = PhaseCapture::new(42);
    for sequence in 0..MAX_RECORDS * 4 {
        capture.feed(record(sequence).as_bytes());
    }
    let (before_cleanup, output) = capture.snapshot_since(0);
    assert_eq!(output.lines().count(), MAX_RECORDS);
    assert!(output.len() <= MAX_RECORDS * (MAX_LINE_BYTES + 1));
    assert!(output.starts_with(&record(MAX_RECORDS * 3)));
    assert!(capture.snapshot_since(before_cleanup).1.is_empty());
    capture.feed(record(999).as_bytes());
    assert_eq!(capture.snapshot_since(before_cleanup).1, record(999));
}

#[test]
fn oversized_or_partial_lines_never_leak_and_capture_resynchronizes() {
    let mut capture = PhaseCapture::new(42);
    capture.feed(&vec![b'x'; MAX_LINE_BYTES * 100]);
    capture.feed(record(1).as_bytes()); // same oversized line: discard it all
    let valid = record(2);
    for chunk in valid.as_bytes().chunks(3) {
        capture.feed(chunk);
    }
    capture.feed(b"private trailing partial request");
    assert_eq!(capture.snapshot_since(0).1, valid);
}

#[cfg(windows)]
#[tokio::test]
async fn stalled_peer_timeout_has_fixed_method_and_phase_without_private_input() {
    use serde_json::json;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    for (method, expected) in [
        ("generate_login", "generate_login"),
        ("private-method-canary", "unknown"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner.sock");
        let name = format!(
            r"\\.\pipe\wispkey-owner-{}",
            path.to_string_lossy().replace(['\\', '/', ':', ' '], "_")
        );
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let peer = tokio::spawn(async move {
            server.connect().await.unwrap();
            let mut reader = BufReader::new(server);
            let mut request = String::new();
            reader.read_line(&mut request).await.unwrap();
            // Deliberately retain the connected peer without responding.
            std::future::pending::<()>().await;
            drop(reader);
        });
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(7), wispkey::owner_ipc::call(&path,
            json!({"id":"private-id-canary", "method":method, "params":{"value":"secret-value-canary"}}))).await;
        peer.abort();
        let diagnostic = result
            .expect("five-second client deadline did not fire")
            .unwrap_err()
            .to_string();
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(diagnostic.contains("response_read phase timed out after 5000 ms"));
        assert!(diagnostic.contains(&format!("method={expected}")));
        for forbidden in [
            "private-method-canary",
            "private-id-canary",
            "secret-value-canary",
        ] {
            assert!(!diagnostic.contains(forbidden));
        }
    }
}
