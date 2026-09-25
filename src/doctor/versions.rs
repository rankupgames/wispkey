use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use super::Check;
use crate::proxy::lifecycle::{MANAGEMENT_TOKEN_HEADER, ProxyMetadata, ProxyState, ProxyStatus};

pub(super) fn check_binary_path() -> Check {
    let current = std::env::current_exe().ok();
    let path = std::env::var_os("PATH");
    let extensions = executable_extensions();
    let resolved = path
        .as_deref()
        .and_then(|path| resolve_path(path, &extensions));
    compare_paths(current.as_deref(), resolved.as_deref())
}

fn executable_extensions() -> Vec<String> {
    #[cfg(windows)]
    {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|extension| {
                extension.starts_with('.')
                    && extension.len() > 1
                    && extension[1..]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric())
            })
            .map(str::to_string)
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![String::new()]
    }
}

// Inspect PATH entries without executing an unknown installation or shell shim.
// Shell aliases/functions and another client's environment are outside this check.
fn resolve_path(path: &OsStr, extensions: &[String]) -> Option<PathBuf> {
    for directory in std::env::split_paths(path) {
        for extension in extensions {
            let candidate = directory.join(format!("wispkey{extension}"));
            if is_executable(&candidate) {
                return std::fs::canonicalize(candidate).ok();
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn compare_paths(current: Option<&Path>, resolved: Option<&Path>) -> Check {
    let current = current.and_then(|path| std::fs::canonicalize(path).ok());
    let Some(current) = current else {
        return Check::warn(
            "binary.path",
            "could not determine the current executable",
            "Check the WispKey installation and this process's PATH.",
        );
    };
    match resolved {
        Some(resolved) if current == resolved => Check::pass(
            "binary.path",
            format!(
                "current executable and first PATH match: {}",
                current.display()
            ),
        ),
        Some(resolved) => Check::warn(
            "binary.path",
            format!(
                "current executable: {}; first PATH match: {}",
                current.display(),
                resolved.display()
            ),
            "Check PATH order or the client launcher. Shell aliases and other clients' environments are not inspected; the other executable was not run.",
        ),
        None => Check::warn(
            "binary.path",
            format!(
                "current executable: {}; wispkey was not found on PATH",
                current.display()
            ),
            "Add the intended WispKey installation to this process's PATH and restart the client.",
        ),
    }
}

pub(super) async fn check_proxy_version(status: &ProxyStatus) -> Check {
    if status.state != ProxyState::Running || !status.healthy {
        return Check::skip("proxy.version", "no healthy owned proxy to compare");
    }
    let Some(metadata) = status
        .metadata
        .as_ref()
        .filter(|m| !m.management_token.is_empty())
    else {
        return Check::warn(
            "proxy.version",
            "running proxy version is unknown: authenticated discovery is unavailable",
            "Check the proxy installation and restart the owned proxy with the intended binary.",
        );
    };
    match fetch_proxy_version(metadata).await {
        Ok(version) if version == env!("CARGO_PKG_VERSION") => Check::pass(
            "proxy.version",
            format!(
                "authenticated proxy and CLI both report {}",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        Ok(_) => Check::warn(
            "proxy.version",
            format!(
                "authenticated running proxy reports a different version from CLI {}",
                env!("CARGO_PKG_VERSION")
            ),
            "Run `wispkey proxy stop`, then start `wispkey serve` with the intended binary when ready.",
        ),
        Err(reason) => Check::warn(
            "proxy.version",
            format!("running proxy version is unknown: {reason}"),
            "Older proxies may not support version diagnostics. Check the installed version and restart the owned proxy when ready.",
        ),
    }
}

#[derive(Deserialize)]
struct ProxyVersion {
    name: String,
    version: String,
    pid: u32,
}

async fn fetch_proxy_version(metadata: &ProxyMetadata) -> Result<String, &'static str> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(750))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| "could not create diagnostic client")?;
    let mut response = client
        .get(format!(
            "{}/api/version",
            metadata.address.trim_end_matches('/')
        ))
        .header(MANAGEMENT_TOKEN_HEADER, &metadata.management_token)
        .send()
        .await
        .map_err(|_| "version request failed or timed out")?;
    if !response.status().is_success() {
        return Err("version endpoint unavailable or authentication rejected");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "version response timed out or failed")?
    {
        if body.len() + chunk.len() > 4096 {
            return Err("version response exceeded the diagnostic limit");
        }
        body.extend_from_slice(&chunk);
    }
    let value: ProxyVersion =
        serde_json::from_slice(&body).map_err(|_| "invalid version response")?;
    if value.name != "wispkey"
        || value.pid != metadata.pid
        || value.version.is_empty()
        || value.version.len() > 64
    {
        return Err("version response did not identify the expected proxy");
    }
    Ok(value.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::CheckStatus;

    fn executable(directory: &Path, extension: &str) -> PathBuf {
        std::fs::create_dir_all(directory).unwrap();
        let file = directory.join(format!("wispkey{extension}"));
        std::fs::write(&file, "fixture; never execute").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::canonicalize(file).unwrap()
    }

    #[test]
    fn detects_shadowing_and_paths_with_spaces_without_executing_files() {
        let root = tempfile::tempdir().unwrap();
        let first_dir = root.path().join("older installation");
        let current_dir = root.path().join("current installation");
        let extension = if cfg!(windows) { ".EXE" } else { "" };
        let first = executable(&first_dir, extension);
        let current = executable(&current_dir, extension);
        let path = std::env::join_paths([&first_dir, &current_dir]).unwrap();
        let resolved = resolve_path(&path, &[extension.into()]).unwrap();
        assert_eq!(resolved, first);
        assert_eq!(
            compare_paths(Some(&current), Some(&resolved)).status,
            CheckStatus::Warn
        );
        assert_eq!(
            compare_paths(Some(&first), Some(&resolved)).status,
            CheckStatus::Pass
        );
        assert_eq!(
            compare_paths(Some(&current), None).status,
            CheckStatus::Warn
        );
    }

    #[cfg(windows)]
    #[test]
    fn honors_pathext_order_for_shell_shims() {
        let root = tempfile::tempdir().unwrap();
        let cmd = executable(root.path(), ".CMD");
        executable(root.path(), ".EXE");
        let path = std::env::join_paths([root.path()]).unwrap();
        assert_eq!(
            resolve_path(&path, &[".CMD".into(), ".EXE".into()]),
            Some(cmd)
        );
    }

    #[cfg(unix)]
    #[test]
    fn ignores_non_executable_files() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let file = executable(root.path(), "");
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = std::env::join_paths([root.path()]).unwrap();
        assert!(resolve_path(&path, &[String::new()]).is_none());
    }

    #[tokio::test]
    async fn compares_authenticated_live_versions_and_handles_old_or_invalid_responses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let pid = std::process::id();
        let valid = |version: &str, pid| {
            serde_json::json!({"name": "wispkey", "version": version, "pid": pid}).to_string()
        };
        for (status, body, expected, message) in [
            (
                "200 OK",
                valid(env!("CARGO_PKG_VERSION"), pid),
                CheckStatus::Pass,
                "both report",
            ),
            (
                "200 OK",
                valid("0.1.0", pid),
                CheckStatus::Warn,
                "different version",
            ),
            (
                "200 OK",
                valid("0.1.0", pid.wrapping_add(1)),
                CheckStatus::Warn,
                "unknown",
            ),
            ("200 OK", "{}".into(), CheckStatus::Warn, "unknown"),
            (
                "200 OK",
                "private-response-value".into(),
                CheckStatus::Warn,
                "unknown",
            ),
            ("200 OK", "x".repeat(4097), CheckStatus::Warn, "limit"),
            (
                "404 Not Found",
                "private-response-value".into(),
                CheckStatus::Warn,
                "unknown",
            ),
            (
                "401 Unauthorized",
                "private-response-value".into(),
                CheckStatus::Warn,
                "unknown",
            ),
            (
                "503 Service Unavailable",
                "vault locked".into(),
                CheckStatus::Warn,
                "unknown",
            ),
            ("302 Found", String::new(), CheckStatus::Warn, "unknown"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    request.extend_from_slice(&byte);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("GET /api/version "));
                assert!(
                    request.contains("x-wispkey-management-token: fixture-management-token\r\n")
                );
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/never-follow\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            });
            let metadata = ProxyMetadata::new(
                address.port(),
                format!("http://{address}"),
                None,
                "fixture-management-token".into(),
                vec![],
            );
            let mut proxy = ProxyStatus::stopped();
            proxy.state = ProxyState::Running;
            proxy.healthy = true;
            proxy.metadata = Some(metadata);
            let check = check_proxy_version(&proxy).await;
            server.await.unwrap();
            assert_eq!(check.status, expected, "{}", check.message);
            assert!(check.message.contains(message), "{}", check.message);
            let output = serde_json::to_string(&check).unwrap();
            assert!(!output.contains("private-response-value"));
            assert!(!output.contains("fixture-management-token"));
        }
    }

    #[tokio::test]
    async fn skips_stopped_or_stale_proxies_without_probing() {
        let mut proxy = ProxyStatus::stopped();
        assert_eq!(check_proxy_version(&proxy).await.status, CheckStatus::Skip);
        proxy.state = ProxyState::Stale;
        assert_eq!(check_proxy_version(&proxy).await.status, CheckStatus::Skip);
        proxy.state = ProxyState::UnknownOwner;
        assert_eq!(check_proxy_version(&proxy).await.status, CheckStatus::Skip);
    }

    #[tokio::test]
    async fn stalled_version_response_has_a_bounded_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let metadata = ProxyMetadata::new(
            address.port(),
            format!("http://{address}"),
            None,
            "fixture-token".into(),
            vec![],
        );
        let result =
            tokio::time::timeout(Duration::from_secs(3), fetch_proxy_version(&metadata)).await;
        server.abort();
        assert!(
            result
                .expect("diagnostic deadline was not enforced")
                .is_err()
        );
    }
}
