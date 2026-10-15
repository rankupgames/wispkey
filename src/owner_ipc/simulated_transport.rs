//! Byte-stream protocol tests, not Unix socket security tests. These exercise
//! the same post-connect exchange as the Unix client without opening a socket.
//! Kernel credentials, permissions and endpoint lifecycle remain integration tests.

use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};

use super::{OwnerIpcError, call_connected};

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .expect("simulated IPC exchange must terminate")
}

async fn read_request(stream: &mut DuplexStream) -> Value {
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).await.unwrap();
    assert!(line.ends_with('\n'), "requests must be newline framed");
    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
async fn fragmented_request_and_response_survive_backpressure() {
    // Capacity one forces partial writes and reads, including inside UTF-8.
    let (client, mut server) = tokio::io::duplex(1);
    let request = json!({"method": "status", "params": {"label": "café\n雪"}});
    let response = json!({"ok": true, "result": {"label": "雪\ncafé"}});
    let (actual, ()) = bounded(async {
        tokio::join!(call_connected(client, request.clone()), async {
            assert_eq!(read_request(&mut server).await, request);
            super::write_line(&mut server, &response).await.unwrap();
        })
    })
    .await;
    assert_eq!(actual.unwrap(), response);
}

#[tokio::test]
async fn response_uses_only_first_frame() {
    let (client, mut server) = tokio::io::duplex(256);
    let (actual, ()) = bounded(async {
        tokio::join!(call_connected(client, json!({"method": "status"})), async {
            read_request(&mut server).await;
            server
                .write_all(b"{\"ok\":true}\nnot-json\n")
                .await
                .unwrap();
        })
    })
    .await;
    assert_eq!(actual.unwrap(), json!({"ok": true}));
}

#[tokio::test]
async fn response_eof_and_malformed_frames_are_protocol_errors() {
    for reply in [b"".as_slice(), b"{\"ok\":", b"not-json\n", b"\n"] {
        let (client, mut server) = tokio::io::duplex(256);
        let (actual, ()) = bounded(async {
            tokio::join!(call_connected(client, json!({"method": "status"})), async {
                read_request(&mut server).await;
                server.write_all(reply).await.unwrap();
                server.shutdown().await.unwrap();
            })
        })
        .await;
        assert!(matches!(actual, Err(OwnerIpcError::Protocol(_))));
        if reply.is_empty() {
            assert!(
                actual
                    .unwrap_err()
                    .to_string()
                    .contains("empty owner IPC response")
            );
        }
    }
}

#[tokio::test]
async fn complete_json_at_eof_preserves_existing_line_reader_contract() {
    let (client, mut server) = tokio::io::duplex(256);
    let (actual, ()) = bounded(async {
        tokio::join!(call_connected(client, json!({"method": "status"})), async {
            read_request(&mut server).await;
            server.write_all(b"{\"ok\":true}").await.unwrap();
            server.shutdown().await.unwrap();
        })
    })
    .await;
    assert_eq!(actual.unwrap(), json!({"ok": true}));
}

#[tokio::test]
async fn invalid_utf8_is_an_io_error() {
    let (client, mut server) = tokio::io::duplex(256);
    let (actual, ()) = bounded(async {
        tokio::join!(call_connected(client, json!({"method": "status"})), async {
            read_request(&mut server).await;
            server.write_all(b"\xff\n").await.unwrap();
        })
    })
    .await;
    assert!(
        matches!(actual, Err(OwnerIpcError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
    );
}

#[tokio::test]
async fn disconnected_peer_fails_request_write() {
    let (client, server) = tokio::io::duplex(1);
    drop(server);
    let result = bounded(call_connected(client, json!({"method": "status"}))).await;
    assert!(
        matches!(result, Err(OwnerIpcError::Io(error)) if error.kind() == std::io::ErrorKind::BrokenPipe)
    );
}

#[tokio::test]
async fn cancelling_a_partial_response_closes_the_stream() {
    let (client, mut server) = tokio::io::duplex(256);
    let mut exchange = Box::pin(call_connected(client, json!({"method": "status"})));
    // Drive the request to completion without timing/scheduler assumptions.
    poll_fn(|cx| {
        assert!(exchange.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    bounded(read_request(&mut server)).await;
    server.write_all(b"{\"ok\":").await.unwrap();
    poll_fn(|cx| {
        assert!(exchange.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // Models caller cancellation (including an outer timeout). The Unix client
    // currently has no built-in timeout; this does not claim to add one.
    drop(exchange);
    assert_eq!(bounded(server.read(&mut [0u8; 1])).await.unwrap(), 0);
    assert_eq!(
        server.write_all(b"true}\n").await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}
