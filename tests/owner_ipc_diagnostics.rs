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

/// Hypothesis experiment, not a replacement for the small-response regression.
/// Keep all four observations, including failures, before asserting delivery.
#[cfg(windows)]
#[tokio::test]
async fn controlled_pipe_delivery_after_delayed_application_read() {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
    use tokio::sync::oneshot;

    #[derive(Default)]
    struct WriteTiming {
        started: Option<Duration>,
        accepted: Option<Duration>,
        wrapper_dropped: Option<Duration>,
    }

    let mut all_delivered = true;
    for (size, padding) in [("small", 96), ("large", 262_144)] {
        for retain_until_ack in [false, true] {
            let lifetime = if retain_until_ack {
                "retained"
            } else {
                "dropped"
            };
            let directory = tempfile::tempdir().unwrap();
            let name = format!(
                r"\\.\pipe\wispkey-experiment-{}",
                directory
                    .path()
                    .to_string_lossy()
                    .replace(['\\', '/', ':', ' '], "_")
            );
            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .out_buffer_size(1024)
                .create(&name)
                .unwrap();
            let mut client = ClientOptions::new().open(&name).unwrap();
            let mut expected = serde_json::to_vec(&serde_json::json!({
                "ok": true, "padding": "x".repeat(padding)
            }))
            .unwrap();
            expected.push(b'\n');
            let response = expected.clone();
            let timing = Arc::new(Mutex::new(WriteTiming::default()));
            let peer_timing = Arc::clone(&timing);
            let (ack, ack_rx) = oneshot::channel();
            let started = Instant::now();
            let mut peer = tokio::spawn(async move {
                server.connect().await?;
                let mut request = String::new();
                BufReader::new(&mut server).read_line(&mut request).await?;
                peer_timing.lock().unwrap().started = Some(started.elapsed());
                server.write_all(&response).await?;
                server.flush().await?;
                peer_timing.lock().unwrap().accepted = Some(started.elapsed());
                if retain_until_ack {
                    let _ = ack_rx.await;
                }
                // This drops the Tokio wrapper. Mio may still retain an OS
                // handle for pending I/O; do not call this OS write completion.
                drop(server);
                peer_timing.lock().unwrap().wrapper_dropped = Some(started.elapsed());
                Ok::<(), std::io::Error>(())
            });
            tokio::time::timeout(Duration::from_secs(5), client.write_all(b"{}\n"))
                .await
                .expect("synthetic request write deadline")
                .expect("synthetic request write");
            let response_started = Instant::now();
            let mut received = Vec::new();
            let mut application_read = None;
            let read_result = tokio::time::timeout(Duration::from_secs(5), async {
                // Always release application consumption after 100 ms; waiting
                // for acceptance would deadlock a legitimately blocked write.
                // Mio can already have issued a 4 KiB OS read in the background.
                tokio::time::sleep(Duration::from_millis(100)).await;
                application_read = Some(started.elapsed());
                BufReader::new(client.take((expected.len() + 1) as u64))
                    .read_until(b'\n', &mut received)
                    .await
            })
            .await;
            let response_ms = response_started.elapsed().as_millis();
            let read_status = match &read_result {
                Err(_) => "deadline",
                Ok(Err(_)) => "io_error",
                Ok(Ok(_)) if received.last() == Some(&b'\n') => "complete_line",
                Ok(Ok(_)) => "incomplete_line",
            };
            let valid = matches!(read_result, Ok(Ok(_))) && received == expected;
            let _ = ack.send(());
            let peer_finished = matches!(
                tokio::time::timeout(Duration::from_secs(1), &mut peer).await,
                Ok(Ok(Ok(())))
            );
            if !peer.is_finished() {
                peer.abort();
                let _ = peer.await;
            }
            let timing = timing.lock().unwrap();
            let acceptance = match (timing.started, timing.accepted, application_read) {
                (_, Some(accepted), Some(read)) if accepted <= read => "accepted_before_read",
                (Some(write), _, Some(read)) if write <= read => "not_yet_accepted",
                _ => "write_not_started_before_read",
            };
            let millis = |time: Option<Duration>| time.map_or(-1, |t| t.as_millis() as i128);
            eprintln!(
                "WKIPC_EXPERIMENT v1 size={size} lifetime={lifetime} acceptance={acceptance} read_status={read_status} expected_bytes={} received_bytes={} valid={valid} peer_finished={peer_finished} write_start_ms={} accepted_ms={} application_read_ms={} wrapper_drop_ms={} response_ms={response_ms}",
                expected.len(),
                received.len(),
                millis(timing.started),
                millis(timing.accepted),
                millis(application_read),
                millis(timing.wrapper_dropped)
            );
            all_delivered &= valid && peer_finished;
        }
    }
    assert!(
        all_delivered,
        "controlled pipe delivery failed; retain all observations above"
    );
}
