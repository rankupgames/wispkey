use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

pub(super) trait ProxyIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> ProxyIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(super) type BoxedProxyIo = Box<dyn ProxyIo>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerMetadata {
    pub transport: String,
    pub address: String,
    pub require_identity: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRequirement {
    Default,
    Require,
    DoNotRequire,
}

impl IdentityRequirement {
    fn apply(self, default: bool) -> bool {
        match self {
            Self::Default => default,
            Self::Require => true,
            Self::DoNotRequire => false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ListenSpec {
    Tcp(SocketAddr),
    Unix(PathBuf),
    Vsock { cid: u32, port: u32 },
    FirecrackerVsock { uds_path: PathBuf, port: u32 },
}

impl ListenSpec {
    pub fn parse(spec: &str) -> Result<Self, TransportError> {
        if let Some(address) = spec.strip_prefix("tcp://") {
            let socket_addr = address.parse::<SocketAddr>().map_err(|_| {
                TransportError::InvalidListenSpec(format!(
                    "invalid TCP listen address '{spec}', expected tcp://127.0.0.1:7700"
                ))
            })?;
            return Ok(Self::Tcp(socket_addr));
        }

        if let Some(path) = spec.strip_prefix("unix:") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(TransportError::InvalidListenSpec(format!(
                    "invalid UDS listen path '{spec}', expected unix:/absolute/path.sock"
                )));
            }
            return Ok(Self::Unix(path));
        }

        if let Some(address) = spec.strip_prefix("vsock://") {
            let (cid, port) = address.rsplit_once(':').ok_or_else(|| {
                TransportError::InvalidListenSpec(format!(
                    "invalid vsock listen address '{spec}', expected vsock://<cid>:<port>"
                ))
            })?;
            let cid = cid.parse::<u32>().map_err(|_| {
                TransportError::InvalidListenSpec(format!("invalid vsock cid in '{spec}'"))
            })?;
            let port = port.parse::<u32>().map_err(|_| {
                TransportError::InvalidListenSpec(format!("invalid vsock port in '{spec}'"))
            })?;
            return Ok(Self::Vsock { cid, port });
        }

        if let Some(address) = spec.strip_prefix("firecracker-vsock:") {
            let (uds_path, port) = address.rsplit_once(':').ok_or_else(|| {
                TransportError::InvalidListenSpec(format!(
                    "invalid Firecracker vsock listen address '{spec}', expected firecracker-vsock:/absolute/path.sock:<port>"
                ))
            })?;
            let uds_path = PathBuf::from(uds_path);
            if !uds_path.is_absolute() {
                return Err(TransportError::InvalidListenSpec(format!(
                    "invalid Firecracker vsock path '{spec}', expected firecracker-vsock:/absolute/path.sock:<port>"
                )));
            }
            let port = port.parse::<u32>().map_err(|_| {
                TransportError::InvalidListenSpec(format!(
                    "invalid Firecracker vsock port in '{spec}'"
                ))
            })?;
            if port == 0 {
                return Err(TransportError::InvalidListenSpec(format!(
                    "invalid Firecracker vsock port in '{spec}': port must be greater than zero"
                )));
            }
            return Ok(Self::FirecrackerVsock { uds_path, port });
        }

        Err(TransportError::InvalidListenSpec(format!(
            "unsupported listen spec '{spec}', expected tcp://host:port, unix:/path.sock, vsock://cid:port, or firecracker-vsock:/path.sock:port"
        )))
    }

    pub fn default_tcp(port: u16) -> Self {
        Self::Tcp(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    pub fn default_requires_identity(&self) -> bool {
        match self {
            Self::Tcp(address) => !address.ip().is_loopback(),
            Self::Unix(_) | Self::Vsock { .. } | Self::FirecrackerVsock { .. } => true,
        }
    }

    pub fn is_non_loopback_tcp(&self) -> bool {
        matches!(self, Self::Tcp(address) if !address.ip().is_loopback())
    }
}

#[derive(Debug, Clone)]
pub struct ListenConfig {
    pub spec: ListenSpec,
    pub require_identity: bool,
}

impl ListenConfig {
    pub fn new(spec: ListenSpec, identity: IdentityRequirement) -> Self {
        let require_identity = identity.apply(spec.default_requires_identity());
        Self {
            spec,
            require_identity,
        }
    }
}

pub(super) struct BoundTransport {
    listener: BoundListener,
    metadata: ListenerMetadata,
    cleanup_path: Option<PathBuf>,
}

impl BoundTransport {
    pub(super) async fn bind(config: ListenConfig) -> Result<Self, TransportError> {
        match config.spec {
            ListenSpec::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await.map_err(|e| {
                    TransportError::Bind(format!(
                        "failed to bind {addr}: {e}. If another process owns this port, WispKey will not terminate it without owned proxy metadata."
                    ))
                })?;
                let actual_addr = listener.local_addr()?;
                Ok(Self {
                    listener: BoundListener::Tcp(listener),
                    metadata: ListenerMetadata {
                        transport: "tcp".to_string(),
                        address: format!("tcp://{actual_addr}"),
                        require_identity: config.require_identity,
                    },
                    cleanup_path: None,
                })
            }
            ListenSpec::Unix(path) => bind_unix(path, config.require_identity).await,
            ListenSpec::Vsock { cid, port } => bind_vsock(cid, port, config.require_identity).await,
            ListenSpec::FirecrackerVsock { uds_path, port } => {
                bind_firecracker_vsock(uds_path, port, config.require_identity).await
            }
        }
    }

    pub(super) fn metadata(&self) -> &ListenerMetadata {
        &self.metadata
    }

    pub(super) fn cleanup_path(&self) -> Option<PathBuf> {
        self.cleanup_path.clone()
    }

    pub(super) async fn accept(&self) -> Result<AcceptedConnection, TransportError> {
        match &self.listener {
            BoundListener::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok(AcceptedConnection {
                    stream: Box::new(stream),
                    peer_label: addr.to_string(),
                })
            }
            #[cfg(unix)]
            BoundListener::Unix(listener) => {
                let (stream, addr) = listener.accept().await?;
                let peer_label = addr
                    .as_pathname()
                    .map(Path::display)
                    .map(|path| path.to_string())
                    .unwrap_or_else(|| "unix-peer".to_string());
                Ok(AcceptedConnection {
                    stream: Box::new(stream),
                    peer_label,
                })
            }
            #[cfg(all(target_os = "linux", feature = "vsock"))]
            BoundListener::Vsock(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok(AcceptedConnection {
                    stream: Box::new(stream),
                    peer_label: format!("vsock://{}:{}", addr.cid(), addr.port()),
                })
            }
        }
    }
}

pub(super) struct AcceptedConnection {
    pub(super) stream: BoxedProxyIo,
    pub(super) peer_label: String,
}

enum BoundListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    #[cfg(all(target_os = "linux", feature = "vsock"))]
    Vsock(tokio_vsock::VsockListener),
}

#[cfg(unix)]
async fn bind_unix(
    path: PathBuf,
    require_identity: bool,
) -> Result<BoundTransport, TransportError> {
    let address = format!("unix:{}", path.display());
    bind_unix_socket(path, "unix", address, require_identity).await
}

#[cfg(unix)]
async fn bind_unix_socket(
    path: PathBuf,
    transport: &str,
    address: String,
    require_identity: bool,
) -> Result<BoundTransport, TransportError> {
    prepare_unix_socket_path(&path)?;
    let listener = tokio::net::UnixListener::bind(&path)?;
    harden_socket_file(&path)?;
    Ok(BoundTransport {
        listener: BoundListener::Unix(listener),
        metadata: ListenerMetadata {
            transport: transport.to_string(),
            address,
            require_identity,
        },
        cleanup_path: Some(path),
    })
}

#[cfg(unix)]
fn prepare_unix_socket_path(path: &Path) -> Result<(), TransportError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        // Only harden a parent directory we create. A pre-existing parent
        // (e.g. /tmp or /run) may be shared or root-owned, where forcing 0700
        // would fail or overreach; the socket file's own 0600 mode is the
        // protection we rely on there.
        if !parent.exists() {
            crate::secure_files::ensure_private_directory(parent)?;
        }
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn firecracker_guest_socket_path(uds_path: &Path, port: u32) -> PathBuf {
    let mut socket_path = uds_path.as_os_str().to_owned();
    socket_path.push(format!("_{port}"));
    socket_path.into()
}

#[cfg(unix)]
async fn bind_firecracker_vsock(
    uds_path: PathBuf,
    port: u32,
    require_identity: bool,
) -> Result<BoundTransport, TransportError> {
    let socket_path = firecracker_guest_socket_path(&uds_path, port);
    let address = format!("firecracker-vsock:{}:{port}", uds_path.display());
    bind_unix_socket(socket_path, "firecracker-vsock", address, require_identity).await
}

#[cfg(not(unix))]
async fn bind_firecracker_vsock(
    _uds_path: PathBuf,
    _port: u32,
    _require_identity: bool,
) -> Result<BoundTransport, TransportError> {
    Err(TransportError::Unsupported(
        "Firecracker vsock transport requires a Unix host".to_string(),
    ))
}

#[cfg(not(unix))]
async fn bind_unix(
    _path: PathBuf,
    _require_identity: bool,
) -> Result<BoundTransport, TransportError> {
    Err(TransportError::Unsupported(
        "unix socket transport is not supported on this platform".to_string(),
    ))
}

#[cfg(unix)]
fn harden_socket_file(path: &Path) -> Result<(), TransportError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
async fn bind_vsock(
    cid: u32,
    port: u32,
    require_identity: bool,
) -> Result<BoundTransport, TransportError> {
    let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(cid, port))?;
    Ok(BoundTransport {
        listener: BoundListener::Vsock(listener),
        metadata: ListenerMetadata {
            transport: "vsock".to_string(),
            address: format!("vsock://{cid}:{port}"),
            require_identity,
        },
        cleanup_path: None,
    })
}

#[cfg(not(all(target_os = "linux", feature = "vsock")))]
async fn bind_vsock(
    _cid: u32,
    _port: u32,
    _require_identity: bool,
) -> Result<BoundTransport, TransportError> {
    Err(TransportError::Unsupported(
        "vsock support not compiled in; rebuild with --features vsock".to_string(),
    ))
}

#[derive(Debug)]
pub enum TransportError {
    InvalidListenSpec(String),
    Bind(String),
    Unsupported(String),
    Io(std::io::Error),
    Vault(crate::core::VaultError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidListenSpec(message) | Self::Bind(message) | Self::Unsupported(message) => {
                f.write_str(message)
            }
            Self::Io(error) => write!(f, "{error}"),
            Self::Vault(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<crate::core::VaultError> for TransportError {
    fn from(error: crate::core::VaultError) -> Self {
        Self::Vault(error)
    }
}

pub(super) fn cleanup_socket(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("failed to remove unix socket {}: {}", path.display(), e),
    }
}
