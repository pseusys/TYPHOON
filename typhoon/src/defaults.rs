//! Default concrete types and re-exports for the most common TYPHOON configurations.
//!
//! Provides [`DefaultExecutor`] (backed by the active runtime feature flag), the
//! [`DefaultServerConnectionHandler`] / [`DefaultClientConnectionHandler`] pair,
//! [`NoopProbeHandler`] (the default no-op active-probing handler), and re-exports
//! [`DecoyFactory`], [`decoy_factory`], and [`random_decoy_factory`] so callers do not need to
//! import from the deeper `flow::decoy` path.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use cfg_if::cfg_if;
use log::{debug, warn};

use crate::bytes::{ByteBuffer, DynamicByteBuffer, StaticByteBuffer};
pub use crate::flow::decoy::{DecoyFactory, decoy_factory, random_decoy_factory};
pub use crate::flow::probe::{ActiveProbeHandler, ProbeFactory, ProbeFlowSender, probe_factory};
use crate::settings::Settings;
use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
pub use crate::trailer::{ClientConnectionHandler, ServerConnectionHandler};
use crate::trailer::{IdentityType, Trailer};
use crate::utils::parse_version;
use crate::utils::random::{SupportRng, get_rng};
pub use crate::utils::sync::AsyncExecutor;

cfg_if! {
    if #[cfg(feature = "tokio")] {
        use tokio::spawn;
        use tokio::runtime::Handle;
        use tokio::task::block_in_place;
    } else if #[cfg(feature = "async-std")] {
        use async_io::block_on as async_io_block_on;
    }
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
        spawn(future);
    }

    fn block_on<F: Future<Output = ()>>(&self, future: F) {
        block_in_place(|| Handle::current().block_on(future));
    }
}

/// async-executor-backed async executor.
#[cfg(feature = "async-std")]
#[derive(Clone)]
pub struct AsyncStdExecutor {
    executor: Arc<async_executor::Executor<'static>>,
}

#[cfg(feature = "async-std")]
impl AsyncExecutor for AsyncStdExecutor {
    fn new() -> Self {
        Self {
            executor: Arc::new(async_executor::Executor::new()),
        }
    }

    fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
        self.executor.spawn(future).detach();
    }

    fn block_on<F: Future<Output = ()>>(&self, future: F) {
        async_io_block_on(future);
    }
}

#[cfg(feature = "async-std")]
impl From<Arc<async_executor::Executor<'static>>> for AsyncStdExecutor {
    fn from(executor: Arc<async_executor::Executor<'static>>) -> Self {
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

/// [`Settings`] parameterized over the default executor for the active runtime feature flag.
pub type DefaultSettings = Settings<DefaultExecutor>;

/// [`Trailer`] parameterized over the default [`StaticByteBuffer`]-backed identity type.
pub type DefaultTrailer = Trailer<StaticByteBuffer>;

/// Server connection handler that produces a fresh random identity for each handshake,
/// returns no server initial data, and checks the client version against `CARGO_PKG_VERSION`.
pub struct DefaultServerConnectionHandler;

impl ServerConnectionHandler<StaticByteBuffer> for DefaultServerConnectionHandler {
    fn generate(&self, _initial_data: &[u8]) -> Option<StaticByteBuffer> {
        Some(StaticByteBuffer::from_slice(get_rng().random_byte_buffer::<DEFAULT_TYPHOON_ID_LENGTH>().slice()))
    }

    fn initial_data(&self, _identity: &StaticByteBuffer) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn verify_version(&self, version_bytes: &[u8]) -> bool {
        let (cli_major, cli_minor, cli_patch) = parse_version(version_bytes);
        let (srv_major, srv_minor, srv_patch) = parse_version(env!("CARGO_PKG_VERSION").as_bytes());
        if cli_major != srv_major {
            warn!("client version major mismatch (client={cli_major}.{cli_minor}.{cli_patch}, server={srv_major}.{srv_minor}.{srv_patch}), rejecting handshake");
            false
        } else if cli_minor != srv_minor {
            warn!("client version minor mismatch (client={cli_major}.{cli_minor}.{cli_patch}, server={srv_major}.{srv_minor}.{srv_patch})");
            true
        } else if cli_patch != srv_patch {
            debug!("client version patch mismatch (client={cli_major}.{cli_minor}.{cli_patch}, server={srv_major}.{srv_minor}.{srv_patch})");
            true
        } else {
            true
        }
    }
}

/// No-op active probe handler. Both [`ActiveProbeHandler::start`] and [`ActiveProbeHandler::process`]
/// do nothing; unidentified packets are dropped silently.
#[derive(Default)]
pub struct NoopProbeHandler;

#[async_trait]
impl<AE: AsyncExecutor + 'static> ActiveProbeHandler<AE> for NoopProbeHandler {
    async fn start(&mut self, _: Weak<dyn ProbeFlowSender>, _: Arc<Settings<AE>>) {}
    async fn process(&mut self, _: DynamicByteBuffer, _: Option<SocketAddr>) {}
}

/// Client connection handler with no custom initial data that encodes `CARGO_PKG_VERSION`
/// into the handshake trailer ID field.
pub struct DefaultClientConnectionHandler;

impl ClientConnectionHandler for DefaultClientConnectionHandler {
    fn initial_data(&self) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn version(&self, length: usize) -> StaticByteBuffer {
        let ver = env!("CARGO_PKG_VERSION").as_bytes();
        let copy_len = ver.len().min(length);
        let mut buf = vec![0u8; length];
        buf[..copy_len].copy_from_slice(&ver[..copy_len]);
        // Pass Vec by value so Arc::from can consume it rather than borrowing a reference.
        StaticByteBuffer::from(buf)
    }
}
