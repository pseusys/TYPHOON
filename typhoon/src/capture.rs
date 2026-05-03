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
//! (`Data`/`Service`/`Decoy`/`Config`), `tailor`, `crypto`, `header`, `payload`, `body`.
//!
//! All capture functions accept a lazy closure so that argument computation —
//! string formatting, allocations, etc. — is entirely skipped at zero cost
//! when the `capture` feature is disabled.

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
#[cfg(all(not(feature = "capture"), feature = "client"))]
pub(crate) struct CaptureContext;

#[cfg(any(feature = "capture", feature = "client"))]
impl CaptureContext {
    /// Create a context for the given flow address.
    #[cfg(feature = "capture")]
    #[inline]
    pub(crate) fn new(flow_addr: SocketAddr) -> Self {
        Self {
            flow_addr,
        }
    }

    #[cfg(not(feature = "capture"))]
    #[inline]
    pub(crate) fn new(_: SocketAddr) -> Self {
        Self
    }

    /// Emit a c2s (client-to-server) packet record.
    ///
    /// `f` is called only when the `capture` feature is enabled; its body
    /// (including any string construction or arithmetic) is never executed
    /// otherwise, giving true zero overhead.
    #[cfg(feature = "capture")]
    pub(crate) fn record_send<F>(&self, f: F)
    where
        F: FnOnce() -> (&'static str, usize, usize, usize, usize, usize),
    {
        let (kind, tailor, crypto, header, payload, body) = f();
        trace!(
            target: "typhoon::capture",
            "{{\"t\":{},\"dir\":\"c2s\",\"flow\":\"{}\",\"kind\":\"{kind}\",\"tailor\":{tailor},\"crypto\":{crypto},\"header\":{header},\"payload\":{payload},\"body\":{body}}}",
            unix_timestamp_ms(),
            self.flow_addr,
        );
    }

    #[allow(clippy::unused_self)]
    #[cfg(not(feature = "capture"))]
    #[inline(always)]
    pub(crate) fn record_send<F>(&self, _: F)
    where
        F: FnOnce() -> (&'static str, usize, usize, usize, usize, usize),
    {
    }
}

/// Emit a configuration record when a flow is established.
///
/// `f` is called only when the `capture` feature is enabled.
/// It should return `(body_mode_description, header_len_bytes, decoy_name)`.
#[cfg(feature = "capture")]
pub(crate) fn record_flow_config<F>(flow_addr: SocketAddr, dir: &str, f: F)
where
    F: FnOnce() -> (String, usize, &'static str),
{
    let (body_mode, header_len, decoy) = f();
    trace!(
        target: "typhoon::capture",
        "{{\"t\":{},\"kind\":\"Config\",\"dir\":\"{dir}\",\"flow\":\"{flow_addr}\",\"body_mode\":\"{body_mode}\",\"header_len\":{header_len},\"decoy\":\"{decoy}\"}}",
        unix_timestamp_ms(),
    );
}

#[cfg(not(feature = "capture"))]
#[inline(always)]
pub(crate) fn record_flow_config<F>(_: SocketAddr, _: &str, _: F)
where
    F: FnOnce() -> (String, usize, &'static str),
{
}

/// Emit an s2c (server-to-client) packet record from the server send path.
///
/// `f` is called only when the `capture` feature is enabled.
#[cfg(feature = "capture")]
pub(crate) fn record_server_send<F>(addr: SocketAddr, f: F)
where
    F: FnOnce() -> (&'static str, usize, usize, usize, usize, usize),
{
    let (kind, tailor, crypto, header, payload, body) = f();
    trace!(
        target: "typhoon::capture",
        "{{\"t\":{},\"dir\":\"s2c\",\"flow\":\"{addr}\",\"kind\":\"{kind}\",\"tailor\":{tailor},\"crypto\":{crypto},\"header\":{header},\"payload\":{payload},\"body\":{body}}}",
        unix_timestamp_ms(),
    );
}

#[cfg(not(feature = "capture"))]
#[inline(always)]
pub(crate) fn record_server_send<F>(_: SocketAddr, _: F)
where
    F: FnOnce() -> (&'static str, usize, usize, usize, usize, usize),
{
}
