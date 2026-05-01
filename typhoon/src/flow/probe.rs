//! Active probing protection: sender trait and handler trait.
//!
//! [`ProbeFlowSender`] gives probe handlers a raw-socket send path that bypasses all TYPHOON
//! framing. [`ActiveProbeHandler`] is the callback interface the flow manager uses to forward
//! every unidentified packet it receives. The default no-op implementation lives in
//! [`crate::defaults`].

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::bytes::DynamicByteBuffer;
use crate::settings::Settings;
use crate::utils::socket::SocketError;
use crate::utils::sync::AsyncExecutor;

/// Object-safe interface for sending raw response packets through the flow manager's socket.
///
/// Implemented individually by `ServerFlowManager` (forwards to `send_to`) and
/// `ClientFlowManager` (forwards to `send` on the connected socket, ignoring `target`).
pub trait ProbeFlowSender: Send + Sync {
    /// Send `packet` as raw bytes to `target`, bypassing all TYPHOON framing.
    fn send_raw<'a>(
        &'a self,
        packet: DynamicByteBuffer,
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), SocketError>> + Send + 'a>>;
}

/// Handler for packets the flow manager could not identify (active probing protection).
///
/// The flow manager calls [`start`] once at startup, then calls [`process`] for every packet
/// whose tailor decryption or verification failed, and — on the server — for every
/// non-handshake, non-decoy packet from an unregistered user.
#[async_trait]
pub trait ActiveProbeHandler<AE: AsyncExecutor + 'static>: Send + Sync {
    /// Called once when the flow manager starts.
    /// `manager` provides a raw-socket send path; `settings` carries runtime configuration.
    async fn start(&mut self, manager: Weak<dyn ProbeFlowSender>, settings: Arc<Settings<AE>>);

    /// Called for each unidentified packet.
    /// `source` is the UDP sender address — `Some` on the server, `None` on the client (the
    /// peer address is fixed for a connected socket and need not be threaded through).
    async fn process(&mut self, packet: DynamicByteBuffer, source: Option<SocketAddr>);
}

/// Factory type for creating active probe handlers.
///
/// A simple no-arg closure — `manager` and `settings` are supplied to each handler via
/// [`ActiveProbeHandler::start`] after construction, so the factory needs no arguments.
pub type ProbeFactory<AE> = Arc<dyn Fn() -> Box<dyn ActiveProbeHandler<AE>> + Send + Sync>;

/// Create a [`ProbeFactory`] from a [`Default`]-constructible [`ActiveProbeHandler`] type.
pub fn probe_factory<AE, PH>() -> ProbeFactory<AE>
where
    AE: AsyncExecutor + 'static,
    PH: ActiveProbeHandler<AE> + Default + 'static,
{
    Arc::new(|| Box::new(PH::default()))
}
