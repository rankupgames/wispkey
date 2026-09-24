//! Restricted target-side executor. It is intentionally a separate binary with
//! fixed production paths and no operation, command, or config CLI arguments.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Stdio;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::process::Command;
use tokio::time::{Instant, timeout_at};
use zeroize::Zeroizing;

const CONFIG_PATH: &str = "/etc/wispkey/helper.toml";
const STORE_PATH: &str = "/var/lib/wispkey-helper/attempts.db";
const MAX_HELLO: usize = 512;
const MAX_DELIVERY: usize = 96 * 1024;
const MAX_SECRET: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    program: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u8,
    attempt_id: String,
    phase: String,
    remaining_ms: u64,
    deadline_unix_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    version: u8,
    attempt_id: String,
    phase: String,
    credential_b64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    version: u8,
    attempt_id: String,
    phase: String,
}

#[derive(Serialize)]
struct Ready<'a> {
    version: u8,
    attempt_id: &'a str,
    phase: &'static str,
}

#[derive(Serialize)]
struct Completion<'a> {
    version: u8,
    attempt_id: &'a str,
    outcome: &'static str,
    count: u32,
    exit_code: Option<i32>,
}

fn config_valid(config: &Config) -> bool {
    if config.version != 1 || config.args.len() > 16 || !absolute_program(&config.program) {
        return false;
    }
    config.args.iter().all(|arg| {
        arg.len() <= 255 && !arg.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
    })
}

fn absolute_program(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 255
        && path.split('/').skip(1).all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
}

fn canonical_attempt(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == id)
}

async fn bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, ()> {
    timeout_at(deadline, async {
        let mut line = Vec::new();
        loop {
            let chunk = reader.fill_buf().await.map_err(|_| ())?;
            if chunk.is_empty() {
                return Err(());
            }
            let count = chunk
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(chunk.len(), |index| index + 1);
            if line
                .len()
                .checked_add(count)
                .is_none_or(|size| size > limit)
            {
                return Err(());
            }
            line.extend_from_slice(&chunk[..count]);
            reader.consume(count);
            if line.last() == Some(&b'\n') {
                line.pop();
                if line
                    .iter()
                    .any(|byte| !byte.is_ascii() || *byte < b' ' || *byte == b'\r')
                {
                    return Err(());
                }
                return Ok(line);
            }
        }
    })
    .await
    .map_err(|_| ())?
}

fn reserve(store: &Path, attempt_id: &str) -> Result<Connection, ()> {
    let mut db = Connection::open_with_flags(
        store,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ())?;
    db.pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| ())?;
    db.pragma_update(None, "synchronous", "FULL")
        .map_err(|_| ())?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('started','succeeded','failed_child','outcome_unknown')));").map_err(|_| ())?;
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| ())?;
    tx.execute(
        "INSERT INTO attempts (id,state) VALUES (?1,'started')",
        params![attempt_id],
    )
    .map_err(|_| ())?;
    tx.commit().map_err(|_| ())?;
    Ok(db)
}

#[cfg(test)]
fn attempt_exists(store: &Path, attempt_id: &str) -> bool {
    let Ok(db) = Connection::open_with_flags(
        store,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return false;
    };
    db.query_row(
        "SELECT 1 FROM attempts WHERE id=?1",
        params![attempt_id],
        |_| Ok(()),
    )
    .is_ok()
}

fn finish(db: &mut Connection, attempt_id: &str, state: &'static str) -> Result<(), ()> {
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| ())?;
    if tx
        .execute(
            "UPDATE attempts SET state=?2 WHERE id=?1 AND state='started'",
            params![attempt_id, state],
        )
        .map_err(|_| ())?
        != 1
    {
        return Err(());
    }
    tx.commit().map_err(|_| ())
}

async fn emit<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: impl Serialize,
    deadline: Instant,
) -> Result<(), ()> {
    let mut line = serde_json::to_vec(&value).map_err(|_| ())?;
    line.push(b'\n');
    timeout_at(deadline, async {
        writer.write_all(&line).await.map_err(|_| ())?;
        writer.flush().await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

#[cfg(unix)]
fn kill_group(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: this helper starts the child in its own session, so -pid is
        // its process group. ESRCH means it has already exited.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
}

#[cfg(unix)]
async fn run_child<R: AsyncBufRead + Unpin>(
    config: &Config,
    secret: &[u8],
    attempt_id: &str,
    reader: &mut R,
    deadline: Instant,
) -> (&'static str, u32, Option<i32>) {
    let mut command = Command::new(&config.program);
    command
        .args(&config.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    let Ok(mut child) = command.spawn() else {
        return ("failed_child", 0, None);
    };
    let Some(mut stdin) = child.stdin.take() else {
        kill_group(&mut child);
        return ("outcome_unknown", 0, None);
    };
    if !matches!(
        timeout_at(deadline, stdin.write_all(secret)).await,
        Ok(Ok(()))
    ) {
        kill_group(&mut child);
        let _ = timeout_at(deadline, child.wait()).await;
        return ("outcome_unknown", 0, None);
    }
    if !matches!(timeout_at(deadline, stdin.shutdown()).await, Ok(Ok(()))) {
        kill_group(&mut child);
        let _ = timeout_at(deadline, child.wait()).await;
        return ("outcome_unknown", 0, None);
    }
    drop(stdin);
    tokio::select! {
        result = child.wait() => match result {
            Ok(status) => match status.code() {
                Some(0) => ("succeeded", 1, Some(0)),
                Some(code @ 1..=255) => ("failed_child", 0, Some(code)),
                _ => ("outcome_unknown", 0, None),
            },
            Err(_) => ("outcome_unknown", 0, None),
        },
        line = bounded_line(reader, MAX_HELLO, deadline) => {
            let _canceled = line.ok().and_then(|raw| serde_json::from_slice::<Cancel>(&raw).ok())
                .is_some_and(|message| message.version == 1 && message.attempt_id == attempt_id && message.phase == "cancel");
            kill_group(&mut child);
            let _ = timeout_at(deadline, child.wait()).await;
            ("outcome_unknown", 0, None)
        },
        _ = tokio::time::sleep_until(deadline) => {
            kill_group(&mut child);
            let _ = timeout_at(deadline, child.wait()).await;
            ("outcome_unknown", 0, None)
        }
    }
}

#[cfg(not(unix))]
async fn run_child<R: AsyncBufRead + Unpin>(
    _config: &Config,
    _secret: &[u8],
    _attempt_id: &str,
    _reader: &mut R,
    _deadline: Instant,
) -> (&'static str, u32, Option<i32>) {
    ("failed_child", 0, None)
}

async fn run_with<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    config: &Config,
    store: &Path,
    input: R,
    mut output: W,
) -> i32 {
    if !config_valid(config) {
        return 1;
    }
    let mut input = BufReader::new(input);
    let initial_deadline = Instant::now() + Duration::from_secs(5);
    let Ok(raw) = bounded_line(&mut input, MAX_HELLO, initial_deadline).await else {
        return 1;
    };
    let Ok(hello) = serde_json::from_slice::<Hello>(&raw) else {
        return 1;
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    if hello.version != 1
        || hello.phase != "hello"
        || !canonical_attempt(&hello.attempt_id)
        || hello.remaining_ms == 0
        || hello.remaining_ms > 60_000
        || hello.deadline_unix_ms <= now_ms
        || hello.deadline_unix_ms > now_ms.saturating_add(60_000)
    {
        return 1;
    }
    let wall_remaining = (hello.deadline_unix_ms - now_ms) as u64;
    let deadline = Instant::now() + Duration::from_millis(hello.remaining_ms.min(wall_remaining));
    let mut db = match reserve(store, &hello.attempt_id) {
        Ok(db) => db,
        Err(_) => {
            let _ = emit(
                &mut output,
                Completion {
                    version: 1,
                    attempt_id: &hello.attempt_id,
                    outcome: "outcome_unknown",
                    count: 0,
                    exit_code: None,
                },
                deadline,
            )
            .await;
            return 1;
        }
    };
    if emit(
        &mut output,
        Ready {
            version: 1,
            attempt_id: &hello.attempt_id,
            phase: "ready",
        },
        deadline,
    )
    .await
    .is_err()
    {
        return 1;
    }
    let raw = match bounded_line(&mut input, MAX_DELIVERY, deadline).await {
        Ok(raw) => Zeroizing::new(raw),
        Err(_) => return 1,
    };
    let delivery: Delivery = match serde_json::from_slice(&raw) {
        Ok(delivery) => delivery,
        Err(_) => return 1,
    };
    let Delivery {
        version,
        attempt_id,
        phase,
        credential_b64,
    } = delivery;
    let encoded = Zeroizing::new(credential_b64);
    if version != 1 || phase != "deliver" || attempt_id != hello.attempt_id {
        return 1;
    }
    let mut secret = match STANDARD.decode(encoded.as_bytes()) {
        Ok(secret) if !secret.is_empty() && secret.len() <= MAX_SECRET => Zeroizing::new(secret),
        _ => return 1,
    };
    if Instant::now() >= deadline {
        return 1;
    }
    let (outcome, count, exit_code) =
        run_child(config, &secret, &hello.attempt_id, &mut input, deadline).await;
    secret.fill(0);
    if finish(&mut db, &hello.attempt_id, outcome).is_err() {
        return 1;
    }
    if emit(
        &mut output,
        Completion {
            version: 1,
            attempt_id: &hello.attempt_id,
            outcome,
            count,
            exit_code,
        },
        deadline,
    )
    .await
    .is_err()
    {
        return 1;
    }
    if outcome == "succeeded" { 0 } else { 1 }
}

#[cfg(unix)]
fn production_config() -> Result<Config, ()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Config and state locations must be installed by an operator, owned by
    // root, and free of path component symlinks.
    for path in [
        Path::new(CONFIG_PATH),
        Path::new(STORE_PATH),
        Path::new(STORE_PATH).parent().ok_or(())?,
    ] {
        let mut prefix = PathBuf::new();
        for component in path.components() {
            prefix.push(component.as_os_str());
            let metadata = std::fs::symlink_metadata(&prefix).map_err(|_| ())?;
            if metadata.file_type().is_symlink() {
                return Err(());
            }
        }
    }
    let metadata = std::fs::metadata(CONFIG_PATH).map_err(|_| ())?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        return Err(());
    }
    let parent = std::fs::metadata(Path::new(STORE_PATH).parent().ok_or(())?).map_err(|_| ())?;
    if !parent.is_dir() || parent.uid() != 0 || parent.permissions().mode() & 0o077 != 0 {
        return Err(());
    }
    let store = std::fs::metadata(STORE_PATH).map_err(|_| ())?;
    if !store.is_file() || store.uid() != 0 || store.permissions().mode() & 0o077 != 0 {
        return Err(());
    }
    let raw = super::identity::read_private_catalog(Path::new(CONFIG_PATH)).map_err(|_| ())?;
    let config: Config = toml::from_str(&raw).map_err(|_| ())?;
    if !config_valid(&config) {
        return Err(());
    }
    let program = Path::new(&config.program);
    let mut prefix = PathBuf::new();
    for component in program.components() {
        prefix.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&prefix).map_err(|_| ())?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(());
        }
        if prefix == program && !metadata.is_file() {
            return Err(());
        }
    }
    Ok(config)
}

/// Binary entry point. Fixed paths and root-owned local policy are mandatory.
pub async fn run() -> i32 {
    #[cfg(unix)]
    {
        // Single-purpose helper: files it creates cannot inherit broad read access.
        unsafe {
            libc::umask(0o077);
        }
        let Ok(config) = production_config() else {
            return 1;
        };
        run_with(
            &config,
            Path::new(STORE_PATH),
            tokio::io::stdin(),
            tokio::io::stdout(),
        )
        .await
    }
    #[cfg(not(unix))]
    {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_and_protocol_reject_unknown_or_unsafe_fields() {
        assert!(
            toml::from_str::<Config>("version = 1\nprogram = '/bin/true'\nunknown = 1").is_err()
        );
        assert!(!config_valid(&Config {
            version: 1,
            program: "/bin/../bin/sh".into(),
            args: vec![]
        }));
        assert!(!config_valid(&Config {
            version: 1,
            program: "/bin/true".into(),
            args: vec!["x\nsecret".into()]
        }));
        assert!(serde_json::from_slice::<Hello>(br#"{"version":2,"attempt_id":"5af05c13-1c0a-4394-a7a3-7f457ff74a40","phase":"hello","remaining_ms":10,"deadline_unix_ms":1,"extra":"x"}"#).is_err());
        assert!(serde_json::from_slice::<Delivery>(br#"{"version":1,"attempt_id":"5af05c13-1c0a-4394-a7a3-7f457ff74a40","phase":"deliver","credential_b64":"eA==","command":"sh"}"#).is_err());
    }

    #[cfg(unix)]
    fn fixture() -> (tempfile::TempDir, Config, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("fixed_helper_child");
        std::fs::write(&program, b"#!/bin/sh\nprintf 'synthetic-stdout-canary\\n'\nprintf 'synthetic-stderr-canary\\n' >&2\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = dir.path().join("attempts.db");
        Connection::open(&store).unwrap();
        let config = Config {
            version: 1,
            program: program.to_string_lossy().into_owned(),
            args: Vec::new(),
        };
        (dir, config, store)
    }

    #[cfg(unix)]
    fn hello(id: &str, duration_ms: u64) -> String {
        format!(
            "{{\"version\":1,\"attempt_id\":\"{id}\",\"phase\":\"hello\",\"remaining_ms\":{duration_ms},\"deadline_unix_ms\":{}}}\n",
            chrono::Utc::now().timestamp_millis() + duration_ms as i64
        )
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_canaries_are_suppressed_and_replay_never_gets_ready() {
        const ID: &str = "5af05c13-1c0a-4394-a7a3-7f457ff74a40";
        let (_dir, config, store) = fixture();
        let (caller, helper) = tokio::io::duplex(128 * 1024);
        let (helper_input, helper_output) = tokio::io::split(helper);
        let task = tokio::spawn({
            let store = store.clone();
            async move { run_with(&config, &store, helper_input, helper_output).await }
        });
        let (caller_input, mut caller_output) = tokio::io::split(caller);
        let mut caller_input = BufReader::new(caller_input);
        caller_output
            .write_all(hello(ID, 5000).as_bytes())
            .await
            .unwrap();
        let mut ready = String::new();
        caller_input.read_line(&mut ready).await.unwrap();
        assert!(ready.contains("\"ready\""));
        assert!(!ready.contains("canary"));
        let delivery = format!(
            "{{\"version\":1,\"attempt_id\":\"{ID}\",\"phase\":\"deliver\",\"credential_b64\":\"{}\"}}\n",
            STANDARD.encode("synthetic-secret-canary")
        );
        caller_output.write_all(delivery.as_bytes()).await.unwrap();
        let mut result = String::new();
        caller_input.read_line(&mut result).await.unwrap();
        assert!(result.contains("\"succeeded\""));
        assert!(!result.contains("canary"));
        assert_eq!(task.await.unwrap(), 0);

        let (caller, helper) = tokio::io::duplex(4096);
        let (helper_input, helper_output) = tokio::io::split(helper);
        let replay_task = tokio::spawn({
            let store = store.clone();
            let config = Config {
                version: 1,
                program: "/bin/true".into(),
                args: vec![],
            };
            async move { run_with(&config, &store, helper_input, helper_output).await }
        });
        let (caller_input, mut caller_output) = tokio::io::split(caller);
        let mut caller_input = BufReader::new(caller_input);
        caller_output
            .write_all(hello(ID, 5000).as_bytes())
            .await
            .unwrap();
        let mut replay = String::new();
        caller_input.read_line(&mut replay).await.unwrap();
        assert!(replay.contains("\"outcome_unknown\""));
        assert!(!replay.contains("\"ready\""));
        assert_eq!(replay_task.await.unwrap(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_exit_42_is_preserved_and_signal_has_no_exit_code() {
        for (script, outcome, code) in [
            ("#!/bin/sh\nexit 42\n", "failed_child", Some(42)),
            ("#!/bin/sh\nkill -TERM $$\n", "outcome_unknown", None),
        ] {
            let (_dir, config, store) = fixture();
            std::fs::write(&config.program, script).unwrap();
            let (caller, helper) = tokio::io::duplex(4096);
            let (helper_input, helper_output) = tokio::io::split(helper);
            let task = tokio::spawn({
                let store = store.clone();
                async move { run_with(&config, &store, helper_input, helper_output).await }
            });
            let (caller_input, mut caller_output) = tokio::io::split(caller);
            let mut caller_input = BufReader::new(caller_input);
            let id = "9a2d2a42-826f-4f2d-a1da-8899b337c985";
            caller_output
                .write_all(hello(id, 5000).as_bytes())
                .await
                .unwrap();
            let mut ready = String::new();
            caller_input.read_line(&mut ready).await.unwrap();
            assert!(ready.contains("\"ready\""));
            let delivery = format!(
                "{{\"version\":1,\"attempt_id\":\"{id}\",\"phase\":\"deliver\",\"credential_b64\":\"{}\"}}\n",
                STANDARD.encode("synthetic-secret")
            );
            caller_output.write_all(delivery.as_bytes()).await.unwrap();
            let mut line = String::new();
            caller_input.read_line(&mut line).await.unwrap();
            let completion: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(completion["outcome"], outcome);
            assert_eq!(completion["exit_code"], serde_json::json!(code));
            assert_eq!(task.await.unwrap(), 1);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expired_or_unknown_hello_never_reserves_attempt() {
        const ID: &str = "5af05c13-1c0a-4394-a7a3-7f457ff74a40";
        let (_dir, config, store) = fixture();
        let (mut caller, helper) = tokio::io::duplex(4096);
        let (helper_input, helper_output) = tokio::io::split(helper);
        let task = tokio::spawn({
            let store = store.clone();
            async move { run_with(&config, &store, helper_input, helper_output).await }
        });
        let invalid = format!(
            "{{\"version\":1,\"attempt_id\":\"{ID}\",\"phase\":\"hello\",\"remaining_ms\":0,\"deadline_unix_ms\":1}}\n"
        );
        caller.write_all(invalid.as_bytes()).await.unwrap();
        assert_eq!(task.await.unwrap(), 1);
        assert!(!attempt_exists(&store, ID));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_child_group_and_persists_uncertain_outcome() {
        const ID: &str = "726f3ec9-e50d-4bd4-a59c-944a76f713c6";
        let (_dir, config, store) = fixture();
        std::fs::write(&config.program, b"#!/bin/sh\n/bin/sleep 5\n").unwrap();
        let (caller, helper) = tokio::io::duplex(4096);
        let (helper_input, helper_output) = tokio::io::split(helper);
        let task = tokio::spawn({
            let store = store.clone();
            async move { run_with(&config, &store, helper_input, helper_output).await }
        });
        let (caller_input, mut caller_output) = tokio::io::split(caller);
        let mut caller_input = BufReader::new(caller_input);
        caller_output
            .write_all(hello(ID, 150).as_bytes())
            .await
            .unwrap();
        let mut ready = String::new();
        caller_input.read_line(&mut ready).await.unwrap();
        assert!(ready.contains("\"ready\""));
        let delivery = format!(
            "{{\"version\":1,\"attempt_id\":\"{ID}\",\"phase\":\"deliver\",\"credential_b64\":\"{}\"}}\n",
            STANDARD.encode("synthetic-secret-canary")
        );
        caller_output.write_all(delivery.as_bytes()).await.unwrap();
        let mut result = String::new();
        tokio::time::timeout(Duration::from_secs(2), caller_input.read_line(&mut result))
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_empty() || result.contains("\"outcome_unknown\""));
        assert_eq!(task.await.unwrap(), 1);
        let db = Connection::open(&store).unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM attempts WHERE id=?1",
                params![ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "outcome_unknown");
    }
}
