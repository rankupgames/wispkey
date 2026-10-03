//! Test-only persistent SSH peer. This is not the production restricted helper.
use super::process_handoff_tests::{CANARY, write};
use base64::{Engine, engine::general_purpose::STANDARD};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey, ssh_key::LineEnding};
use russh::{Channel, ChannelId, server};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default, serde::Serialize)]
struct Counts {
    connections: usize,
    rejected_keys: usize,
    reservations: usize,
    deliveries: usize,
    replays: usize,
}

struct Peer {
    allowed_key: PublicKey,
    counts: Arc<Mutex<Counts>>,
    attempts: Arc<Mutex<rusqlite::Connection>>,
    mode: Option<String>,
    pending: Vec<u8>,
    attempt: Option<String>,
}

impl server::Handler for Peer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if user == "restricted" && key == &self.allowed_key {
            Ok(server::Auth::Accept)
        } else {
            self.counts.lock().unwrap().rejected_keys += 1;
            Ok(server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let mode = std::str::from_utf8(command)
            .ok()
            .and_then(|s| s.strip_prefix("/fixture/"));
        if let Some(mode @ ("deliver" | "stdout" | "stderr" | "malformed" | "lost-ack")) = mode {
            self.mode = Some(mode.to_owned());
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        assert!(self.mode.is_some());
        self.pending.extend_from_slice(data);
        assert!(self.pending.len() <= 4096, "fixture protocol bound");
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Value = serde_json::from_slice(&self.pending[..end]).unwrap();
            self.pending.drain(..=end);
            let attempt = line["attempt_id"].as_str().unwrap();
            if self.attempt.is_none() {
                assert_eq!(line["phase"], "hello");
                assert!(uuid::Uuid::parse_str(attempt).is_ok());
                let reserved = self
                    .attempts
                    .lock()
                    .unwrap()
                    .execute(
                        "INSERT OR IGNORE INTO attempts(id, delivered) VALUES (?1, 0)",
                        [attempt],
                    )
                    .unwrap();
                if reserved == 0 {
                    self.counts.lock().unwrap().replays += 1;
                    let mut reply = serde_json::to_vec(&json!({"version":1,"attempt_id":attempt,
                        "outcome":"outcome_unknown","count":0,"exit_code":null}))
                    .unwrap();
                    reply.push(b'\n');
                    session.data(channel, reply)?;
                    session.close(channel)?;
                    return Ok(());
                }
                self.counts.lock().unwrap().reservations += 1;
                self.attempt = Some(attempt.to_owned());
                // Keep the first HTTP invocation active while its concurrent duplicate arrives.
                tokio::time::sleep(Duration::from_millis(150)).await;
                let mut reply =
                    serde_json::to_vec(&json!({"version":1,"attempt_id":attempt,"phase":"ready"}))
                        .unwrap();
                reply.push(b'\n');
                session.data(channel, reply)?;
            } else {
                assert_eq!(line["phase"], "deliver");
                assert_eq!(Some(attempt), self.attempt.as_deref());
                let value = STANDARD
                    .decode(line["credential_b64"].as_str().unwrap())
                    .unwrap();
                assert!(value == CANARY.as_bytes(), "unexpected synthetic delivery");
                assert_eq!(
                    self.attempts
                        .lock()
                        .unwrap()
                        .execute(
                            "UPDATE attempts SET delivered=1 WHERE id=?1 AND delivered=0",
                            [attempt]
                        )
                        .unwrap(),
                    1
                );
                self.counts.lock().unwrap().deliveries += 1;
                match self.mode.as_deref().unwrap() {
                    "stdout" => session.data(channel, format!("{CANARY}\n").into_bytes())?,
                    "stderr" => session.extended_data(channel, 1, CANARY.as_bytes().to_vec())?,
                    "malformed" => session.data(
                        channel,
                        format!("{{\"error\":\"{CANARY}\"}}\n").into_bytes(),
                    )?,
                    "lost-ack" => {} // Destination received the value but acknowledges nothing.
                    "deliver" => {
                        let mut reply =
                            serde_json::to_vec(&json!({"version":1,"attempt_id":attempt,
                            "outcome":"succeeded","count":1,"exit_code":0}))
                            .unwrap();
                        reply.push(b'\n');
                        session.data(channel, reply)?;
                        session.exit_status_request(channel, 0)?;
                    }
                    _ => unreachable!(),
                }
                session.close(channel)?;
            }
        }
        Ok(())
    }
}

pub(super) async fn run(root: &Path) {
    let private_key =
        || PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let host = private_key();
    let client = private_key();
    let wrong = private_key();
    let key_path = root.join("destination/identity");
    let wrong_path = root.join("destination/wrong-identity");
    for (path, key) in [(&key_path, &client), (&wrong_path, &wrong)] {
        crate::secure_files::write_private(
            path,
            key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
    }
    let fingerprint = host.public_key().fingerprint(HashAlg::Sha256).to_string();
    let allowed_key = client.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![host],
        window_size: 128,
        ..Default::default()
    });
    let counts = Arc::new(Mutex::new(Counts::default()));
    let path = root.join("destination/attempts.db");
    crate::secure_files::write_private(&path, b"").unwrap();
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute(
        "CREATE TABLE attempts(id TEXT PRIMARY KEY, delivered INTEGER NOT NULL)",
        [],
    )
    .unwrap();
    let attempts = Arc::new(Mutex::new(db));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    write(
        &root.join("target.json"),
        &json!({"address":"127.0.0.1","port":listener.local_addr().unwrap().port(),
        "account":"restricted","host_key_algorithm":"ssh-ed25519","host_key_sha256":fingerprint,
        "helper_path":"/fixture/deliver","identity_file":key_path,"wrong_identity_file":wrong_path}),
    );
    let mut sessions = tokio::task::JoinSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, _) = accepted.unwrap();
                counts.lock().unwrap().connections += 1;
                let peer = Peer { allowed_key:allowed_key.clone(), counts:counts.clone(), attempts:attempts.clone(),
                    mode:None, pending:Vec::new(), attempt:None };
                let config = config.clone();
                sessions.spawn(async move {
                    // Rejected pins/keys legitimately close the SSH handshake.
                    if let Ok(session) = server::run_stream(config, socket, peer).await { let _ = session.await; }
                });
            }
            completed = sessions.join_next(), if !sessions.is_empty() => { completed.unwrap().unwrap(); }
            _ = tokio::time::sleep(Duration::from_millis(25)) => {
                if root.join("finish.json").exists() { break; }
                assert!(tokio::time::Instant::now() < deadline, "destination deadline");
            }
        }
    }
    sessions.abort_all();
    while let Some(result) = sessions.join_next().await {
        if let Err(error) = result {
            assert!(error.is_cancelled(), "destination fixture task failed");
        }
    }
    let counts = serde_json::to_value(&*counts.lock().unwrap()).unwrap();
    let db = attempts.lock().unwrap();
    let persisted: (u64, u64) = db
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(delivered),0) FROM attempts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    write(
        &root.join("destination-result.json"),
        &json!({"counts":counts,"persisted_attempts":persisted.0,"persisted_deliveries":persisted.1}),
    );
}
