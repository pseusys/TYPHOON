/// ClientPool tests: multiplexed `receive`/`send` keyed by identity, `connected_ids()` for pool
/// membership, and `on_connect`/`on_disconnect` lifecycle semantics — `on_connect` reports
/// whether each handshake was fresh or a re-handshake collision; `on_disconnect` only fires on
/// genuine disconnection.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use typhoon::bytes::StaticByteBuffer;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use typhoon::socket::{ServerBuilder, ServerConnectionHandler, ServerFlowConfiguration};

use super::common::{connect_simple, default_settings, empty_flow_config, free_addr, server_key_pair};

/// Shared `on_connect`/`on_disconnect` call counts, used by both test connection handlers below.
#[derive(Default)]
struct Counters {
    fresh_connects: AtomicUsize,
    reconnects: AtomicUsize,
    disconnects: AtomicUsize,
}

impl Counters {
    fn on_connect(&self, existing: bool) {
        let counter = if existing {
            &self.reconnects
        } else {
            &self.fresh_connects
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    fn on_disconnect(&self) {
        self.disconnects.fetch_add(1, Ordering::SeqCst);
    }
}

/// Wraps `DefaultServerConnectionHandler` (random identities) and records connect/disconnect calls.
struct CountingConnectionHandler {
    inner: DefaultServerConnectionHandler,
    counters: Arc<Counters>,
}

impl ServerConnectionHandler<StaticByteBuffer> for CountingConnectionHandler {
    fn generate(&self, initial_data: &[u8]) -> Option<StaticByteBuffer> {
        self.inner.generate(initial_data)
    }

    fn initial_data(&self, identity: &StaticByteBuffer) -> StaticByteBuffer {
        self.inner.initial_data(identity)
    }

    fn verify_version(&self, version_bytes: &[u8]) -> bool {
        self.inner.verify_version(version_bytes)
    }

    fn on_connect(&self, _identity: &StaticByteBuffer, existing: bool) {
        self.counters.on_connect(existing);
    }

    fn on_disconnect(&self, _identity: &StaticByteBuffer) {
        self.counters.on_disconnect();
    }
}

/// Always derives the same fixed identity (any client certificate maps to it), so a second
/// handshake against this server is a re-handshake collision rather than a fresh connection.
struct FixedCountingConnectionHandler {
    counters: Arc<Counters>,
}

impl ServerConnectionHandler<StaticByteBuffer> for FixedCountingConnectionHandler {
    fn generate(&self, _initial_data: &[u8]) -> Option<StaticByteBuffer> {
        Some(StaticByteBuffer::from_slice(&[0x77u8; DEFAULT_TYPHOON_ID_LENGTH]))
    }

    fn initial_data(&self, _identity: &StaticByteBuffer) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn verify_version(&self, _version_bytes: &[u8]) -> bool {
        true
    }

    fn on_connect(&self, _identity: &StaticByteBuffer, existing: bool) {
        self.counters.on_connect(existing);
    }

    fn on_disconnect(&self, _identity: &StaticByteBuffer) {
        self.counters.on_disconnect();
    }
}

// Test: several clients connect through one ClientPool; receive() tags each packet with the
// right identity, send() reaches the right client only, and connected_ids() reflects membership.
#[tokio::test(flavor = "multi_thread")]
async fn test_pool_multiplexes_clients_by_identity() {
    let settings = default_settings();
    let addr = free_addr();
    let key_pair = server_key_pair();
    let certs: Vec<_> = (0..3).map(|_| key_pair.to_client_certificate(vec![addr])).collect();

    let pool: Arc<_> = Arc::new(ServerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(ServerFlowConfiguration::with_address(empty_flow_config(), addr)).with_settings(settings.clone()).build_pool().await.expect("pool should build"));
    pool.start().await;

    let pool_handle = pool.clone();
    settings.executor().spawn(async move {
        while let Ok((id, data)) = pool_handle.receive().await {
            let _ = pool_handle.send(&id, data).await;
        }
    });

    for (i, cert) in certs.into_iter().enumerate() {
        let socket = connect_simple(cert, settings.clone(), DefaultClientConnectionHandler).await;
        let msg = format!("client-{i}");
        socket.send_bytes(msg.as_bytes()).await.expect("send should succeed");
        let resp = socket.receive_bytes().await.expect("receive should succeed");
        assert_eq!(resp, msg.as_bytes(), "client {i} got the wrong echo");
    }

    assert_eq!(pool.connected_ids().await.len(), 3, "all three clients should still be connected");
}

// Test: ClientPool::disconnect() sends a TERMINATION packet, the client observes the connection
// end, on_disconnect fires exactly once, and the identity drops out of connected_ids().
#[tokio::test(flavor = "multi_thread")]
async fn test_pool_disconnect_fires_on_disconnect_once() {
    let settings = default_settings();
    let addr = free_addr();
    let key_pair = server_key_pair();
    let cert = key_pair.to_client_certificate(vec![addr]);
    let counters = Arc::new(Counters::default());

    let handler = CountingConnectionHandler {
        inner: DefaultServerConnectionHandler,
        counters: counters.clone(),
    };
    let pool: Arc<_> = Arc::new(ServerBuilder::<StaticByteBuffer, DefaultExecutor, CountingConnectionHandler>::new(key_pair, handler).add_flow(ServerFlowConfiguration::with_address(empty_flow_config(), addr)).with_settings(settings.clone()).build_pool().await.expect("pool should build"));
    pool.start().await;

    let socket = connect_simple(cert, settings.clone(), DefaultClientConnectionHandler).await;
    socket.send_bytes(b"hello").await.expect("send should succeed");

    let (id, _) = pool.receive().await.expect("receive should succeed");
    assert_eq!(pool.connected_ids().await, vec![id.clone()], "the connected client should be visible before disconnect()");
    assert_eq!(counters.fresh_connects.load(Ordering::SeqCst), 1, "on_connect should fire once with existing=false for a brand-new identity");
    assert_eq!(counters.reconnects.load(Ordering::SeqCst), 0, "on_connect must not report existing=true for a brand-new identity");

    pool.disconnect(&id).await;

    // The client should observe the TERMINATION (or at least the channel closing).
    let result = socket.receive_bytes().await;
    assert!(result.is_err(), "client should observe the connection ending after disconnect()");

    assert_eq!(counters.disconnects.load(Ordering::SeqCst), 1, "on_disconnect should fire exactly once");

    // The pool's own bookkeeping is cleaned up by the client's pump task, asynchronously with
    // respect to disconnect() returning — poll briefly instead of asserting immediately.
    for _ in 0..50 {
        if pool.connected_ids().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(pool.connected_ids().await.is_empty(), "the identity should drop out of connected_ids() after disconnect()");

    // A second disconnect() on the now-unknown identity must be a harmless no-op.
    pool.disconnect(&id).await;
    assert_eq!(counters.disconnects.load(Ordering::SeqCst), 1, "on_disconnect must not fire again for an already-gone identity");
}

// Test: a re-handshake that reuses the same identity displaces the old connection — on_connect
// reports existing=true for it instead of firing on_disconnect, so a caller can tell a
// genuinely new identity from one merely reconnecting without its own bookkeeping.
#[tokio::test(flavor = "multi_thread")]
async fn test_pool_rehandshake_reports_existing_and_skips_on_disconnect() {
    let settings = default_settings();
    let addr = free_addr();
    let key_pair = server_key_pair();
    let cert_a = key_pair.to_client_certificate(vec![addr]);
    let cert_b = key_pair.to_client_certificate(vec![addr]);
    let counters = Arc::new(Counters::default());

    let handler = FixedCountingConnectionHandler {
        counters: counters.clone(),
    };
    let pool: Arc<_> = Arc::new(ServerBuilder::<StaticByteBuffer, DefaultExecutor, FixedCountingConnectionHandler>::new(key_pair, handler).add_flow(ServerFlowConfiguration::with_address(empty_flow_config(), addr)).with_settings(settings.clone()).build_pool().await.expect("pool should build"));
    pool.start().await;

    let pool_handle = pool.clone();
    settings.executor().spawn(async move {
        while let Ok((id, data)) = pool_handle.receive().await {
            let _ = pool_handle.send(&id, data).await;
        }
    });

    let socket_a = connect_simple(cert_a, settings.clone(), DefaultClientConnectionHandler).await;
    socket_a.send_bytes(b"from-a").await.expect("send should succeed");
    assert_eq!(socket_a.receive_bytes().await.expect("receive should succeed"), b"from-a");
    assert_eq!(pool.connected_ids().await.len(), 1, "exactly one identity should be connected before the rebind");
    assert_eq!(counters.fresh_connects.load(Ordering::SeqCst), 1, "the first connection should report existing=false");
    assert_eq!(counters.reconnects.load(Ordering::SeqCst), 0);

    // Same fixed identity, fresh handshake — a re-handshake collision from the server's view.
    let socket_b = connect_simple(cert_b, settings.clone(), DefaultClientConnectionHandler).await;
    socket_b.send_bytes(b"from-b").await.expect("send should succeed");
    assert_eq!(socket_b.receive_bytes().await.expect("receive should succeed"), b"from-b");

    assert_eq!(counters.fresh_connects.load(Ordering::SeqCst), 1, "the rebind must not be reported as a second fresh connect");
    assert_eq!(counters.reconnects.load(Ordering::SeqCst), 1, "the rebind should report existing=true exactly once");

    // Give the displaced connection's pump task a moment to observe the replacement.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(counters.disconnects.load(Ordering::SeqCst), 0, "re-handshake must not fire on_disconnect");
    assert_eq!(pool.connected_ids().await.len(), 1, "the rebind must not leave a duplicate or stale entry");
}
