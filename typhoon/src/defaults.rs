use std::future::Future;

use cfg_if::cfg_if;
use log::{debug, warn};

use crate::bytes::{ByteBuffer, StaticByteBuffer};
use crate::settings::Settings;
use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use crate::tailor::{IdentityType, Tailor};
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::sync::AsyncExecutor;

pub use crate::tailor::{ClientConnectionHandler, ServerConnectionHandler};

/// Parse a version byte slice of the form `"major[.minor[.patch[-tag]]]"` into `(major, minor, patch)`.
/// Bytes after the first null are ignored. Components that cannot be parsed default to `0`.
fn parse_version(bytes: &[u8]) -> (u64, u64, u64) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = std::str::from_utf8(&bytes[..end]).unwrap_or("").trim();
    let base = s.split('-').next().unwrap_or(s);
    let mut parts = base.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

impl IdentityType for StaticByteBuffer {
    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), DEFAULT_TYPHOON_ID_LENGTH, "invalid bytes identity length: expected {}, got {}", DEFAULT_TYPHOON_ID_LENGTH, bytes.len());
        Self::from_slice(bytes)
    }

    fn to_bytes(&self) -> &[u8] {
        self.slice()
    }

    fn length() -> usize {
        DEFAULT_TYPHOON_ID_LENGTH
    }
}

/// Tokio-backed async executor.
#[cfg(feature = "tokio")]
#[derive(Clone)]
pub struct TokioExecutor;

#[cfg(feature = "tokio")]
impl AsyncExecutor for TokioExecutor {
    fn new() -> Self {
        Self
    }

    fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
        tokio::spawn(future);
    }
}

/// async-executor-backed async executor.
#[cfg(feature = "async-std")]
#[derive(Clone)]
pub struct AsyncStdExecutor {
    executor: std::sync::Arc<async_executor::Executor<'static>>,
}

#[cfg(feature = "async-std")]
impl AsyncExecutor for AsyncStdExecutor {
    fn new() -> Self {
        Self {
            executor: std::sync::Arc::new(async_executor::Executor::new()),
        }
    }

    fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
        self.executor.spawn(future).detach();
    }
}

#[cfg(feature = "async-std")]
impl From<std::sync::Arc<async_executor::Executor<'static>>> for AsyncStdExecutor {
    fn from(executor: std::sync::Arc<async_executor::Executor<'static>>) -> Self {
        Self {
            executor,
        }
    }
}

// Default definitions:

cfg_if! {
    if #[cfg(feature = "tokio")] {
        /// The default executor type selected by the active feature flag.
        pub type DefaultExecutor = TokioExecutor;
    } else if #[cfg(feature = "async-std")] {
        /// The default executor type selected by the active feature flag.
        pub type DefaultExecutor = AsyncStdExecutor;
    }
}

pub type DefaultSettings = Settings<DefaultExecutor>;

pub type DefaultTailor = Tailor<StaticByteBuffer>;

/// Server connection handler that produces a fresh random identity for each handshake,
/// returns no server initial data, and checks the client version against `CARGO_PKG_VERSION`.
pub struct DefaultServerConnectionHandler;

impl ServerConnectionHandler<StaticByteBuffer> for DefaultServerConnectionHandler {
    fn generate(&self, _initial_data: &[u8]) -> StaticByteBuffer {
        get_rng().random_byte_buffer::<DEFAULT_TYPHOON_ID_LENGTH>()
    }

    fn initial_data(&self, _identity: &StaticByteBuffer) -> Vec<u8> {
        Vec::new()
    }

    fn verify_version(&self, version_bytes: &[u8]) -> bool {
        let (cli_major, cli_minor, cli_patch) = parse_version(version_bytes);
        let (srv_major, srv_minor, srv_patch) = parse_version(env!("CARGO_PKG_VERSION").as_bytes());
        if cli_major != srv_major {
            warn!("client version major mismatch (client={}.{}.{}, server={}.{}.{}), rejecting handshake",
                cli_major, cli_minor, cli_patch, srv_major, srv_minor, srv_patch);
            false
        } else if cli_minor != srv_minor {
            warn!("client version minor mismatch (client={}.{}.{}, server={}.{}.{})",
                cli_major, cli_minor, cli_patch, srv_major, srv_minor, srv_patch);
            true
        } else if cli_patch != srv_patch {
            debug!("client version patch mismatch (client={}.{}.{}, server={}.{}.{})",
                cli_major, cli_minor, cli_patch, srv_major, srv_minor, srv_patch);
            true
        } else {
            true
        }
    }
}

/// Client connection handler with no custom initial data that encodes `CARGO_PKG_VERSION`
/// into the handshake tailor ID field.
pub struct DefaultClientConnectionHandler;

impl ClientConnectionHandler for DefaultClientConnectionHandler {
    fn initial_data(&self) -> Vec<u8> {
        Vec::new()
    }

    fn version(&self, length: usize) -> Vec<u8> {
        let ver = env!("CARGO_PKG_VERSION").as_bytes();
        let mut buf = vec![0u8; length];
        let copy_len = ver.len().min(length);
        buf[..copy_len].copy_from_slice(&ver[..copy_len]);
        buf
    }
}
