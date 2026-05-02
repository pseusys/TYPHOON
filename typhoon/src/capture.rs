//! Packet capture tracing for flow visualisation.
//!
//! Enabled by the `capture` feature. Emit JSONL records to the
//! `typhoon::capture` log target at `TRACE` level:
//!
//! ```text
//! RUST_LOG=typhoon::capture=trace cargo run --features capture --example hello_world
//! ```
//!
//! Each line is a self-contained JSON object with fields:
//! `t` (unix ms), `dir` (`c2s`/`s2c`), `flow` (addr), `kind`
//! (`Data`/`Service`/`Decoy`), `tailor`, `crypto`, `header`, `payload`, `body`.

use std::net::SocketAddr;

use cfg_if::cfg_if;

cfg_if!(
    if #[cfg(feature = "capture")] {
        use log::trace;
        use crate::utils::unix_timestamp_ms;
    }
);

/// Per-flow capture context embedded in [`crate::flow::common::FlowSendInternal`].
///
/// Zero-sized (no overhead) when the `capture` feature is disabled.
#[cfg(feature = "capture")]
pub(crate) struct CaptureContext {
    flow_addr: SocketAddr,
}

/// Zero-sized stand-in used when the `capture` feature is disabled.
#[cfg(not(feature = "capture"))]
pub(crate) struct CaptureContext;

impl CaptureContext {
    /// Create a context for the given flow address.
    #[cfg(feature = "capture")]
    #[inline]
    pub(crate) fn new(flow_addr: SocketAddr) -> Self {
        Self { flow_addr }
    }

    #[cfg(not(feature = "capture"))]
    #[inline(always)]
    pub(crate) fn new(_: SocketAddr) -> Self {
        Self
    }

    /// Emit a c2s (client-to-server) packet record.
    #[cfg(feature = "capture")]
    pub(crate) fn record_send(&self, kind: &str, tailor: usize, crypto: usize, header: usize, payload: usize, body: usize) {
        trace!(
            target: "typhoon::capture",
            "{{\"t\":{},\"dir\":\"c2s\",\"flow\":\"{}\",\"kind\":\"{kind}\",\"tailor\":{tailor},\"crypto\":{crypto},\"header\":{header},\"payload\":{payload},\"body\":{body}}}",
            unix_timestamp_ms(),
            self.flow_addr,
        );
    }

    #[cfg(not(feature = "capture"))]
    #[inline(always)]
    pub(crate) fn record_send(&self, _: &str, _: usize, _: usize, _: usize, _: usize, _: usize) {}
}

/// Emit an s2c (server-to-client) packet record from the server send path.
#[cfg(feature = "capture")]
pub(crate) fn record_server_send(addr: SocketAddr, kind: &str, tailor: usize, crypto: usize, header: usize, payload: usize, body: usize) {
    trace!(
        target: "typhoon::capture",
        "{{\"t\":{},\"dir\":\"s2c\",\"flow\":\"{addr}\",\"kind\":\"{kind}\",\"tailor\":{tailor},\"crypto\":{crypto},\"header\":{header},\"payload\":{payload},\"body\":{body}}}",
        unix_timestamp_ms(),
    );
}

#[cfg(not(feature = "capture"))]
#[inline(always)]
pub(crate) fn record_server_send(_: SocketAddr, _: &str, _: usize, _: usize, _: usize, _: usize, _: usize) {}
