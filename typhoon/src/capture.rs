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
//! (`Data`/`Service`/`Decoy`/`Config`), `trailer`, `crypto`, `header`, `payload`, `body`.
//!
//! All capture functions accept a lazy closure so that argument computation —
//! string formatting, allocations, etc. — is entirely skipped at zero cost
//! when the `capture` feature is disabled.

use std::net::SocketAddr;
#[cfg(feature = "capture")]
use std::sync::atomic::{AtomicU64, Ordering};

use cfg_if::cfg_if;

cfg_if!(
    if #[cfg(feature = "capture")] {
        use log::trace;
        use crate::utils::unix_timestamp_ms;
    }
);

/// Process-global count of packets dropped because a named bounded drain channel was full.
/// Only tracked with the `capture` feature; incremented from [`record_drain_drop`], which the
/// bounded queue calls only for queues created with a `Some(name)` label (see
/// `crate::utils::sync::create_bounded_notify_queue`).
#[cfg(feature = "capture")]
static DRAIN_DROPS: AtomicU64 = AtomicU64::new(0);

/// Process-global count of drain-task receive errors. Only tracked with the `capture` feature.
#[cfg(feature = "capture")]
static RECV_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Record a bounded-drain-channel overflow drop. No-op without the `capture` feature.
#[cfg(feature = "capture")]
#[inline]
pub(crate) fn record_drain_drop() {
    DRAIN_DROPS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "capture"))]
#[inline(always)]
pub(crate) fn record_drain_drop() {}

/// Record a drain-task receive error. No-op without the `capture` feature.
#[cfg(feature = "capture")]
#[inline]
pub(crate) fn record_recv_error() {
    RECV_ERRORS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "capture"))]
#[inline(always)]
pub(crate) fn record_recv_error() {}

/// Emit the accumulated loss counters as a `Loss` JSONL record on the `typhoon::capture`
/// target. Intended to be called once, at server shutdown, by a load-testing harness.
/// No-op without the `capture` feature.
#[cfg(feature = "capture")]
pub fn record_loss() {
    trace!(
        target: "typhoon::capture",
        "{{\"t\":{},\"kind\":\"Loss\",\"drain_drops\":{},\"recv_errors\":{}}}",
        unix_timestamp_ms(),
        DRAIN_DROPS.load(Ordering::Relaxed),
        RECV_ERRORS.load(Ordering::Relaxed),
    );
}

/// No-op stand-in for [`record_loss`] when the `capture` feature is disabled.
#[cfg(not(feature = "capture"))]
#[inline(always)]
pub fn record_loss() {}

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
        let (kind, trailer, crypto, header, payload, body) = f();
        trace!(
            target: "typhoon::capture",
            "{{\"t\":{},\"dir\":\"c2s\",\"flow\":\"{}\",\"kind\":\"{kind}\",\"trailer\":{trailer},\"crypto\":{crypto},\"header\":{header},\"payload\":{payload},\"body\":{body}}}",
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
    let (kind, trailer, crypto, header, payload, body) = f();
    trace!(
        target: "typhoon::capture",
        "{{\"t\":{},\"dir\":\"s2c\",\"flow\":\"{addr}\",\"kind\":\"{kind}\",\"trailer\":{trailer},\"crypto\":{crypto},\"header\":{header},\"payload\":{payload},\"body\":{body}}}",
        unix_timestamp_ms(),
    );
}

#[cfg(all(not(feature = "capture"), feature = "server"))]
#[inline(always)]
pub(crate) fn record_server_send<F>(_: SocketAddr, _: F)
where
    F: FnOnce() -> (&'static str, usize, usize, usize, usize, usize),
{
}
