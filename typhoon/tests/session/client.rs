use std::future::ready;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::bytes::{ByteBufferMut, DynamicByteBuffer, FixedByteBuffer, StaticByteBuffer};
use crate::cache::SharedValue;
use crate::certificate::ServerKeyPair;
use crate::crypto::ClientCryptoTool;
use crate::defaults::{DefaultClientConnectionHandler, DefaultExecutor};
use crate::flow::{FlowControllerError, FlowManager};
use crate::session::SessionControllerError;
use crate::session::client::ClientSessionManager;
use crate::session::common::SessionManager;
use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use crate::settings::{Settings, SettingsBuilder, keys};
use crate::trailer::{ReturnCode, Trailer};

// ── Test infrastructure ───────────────────────────────────────────────────────

fn fast_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(SettingsBuilder::new().set(&keys::HEALTH_CHECK_NEXT_IN_MIN, 60_000u64).set(&keys::HEALTH_CHECK_NEXT_IN_MAX, 120_000u64).build().unwrap())
}

fn test_identity() -> StaticByteBuffer {
    StaticByteBuffer::from_slice(&[0u8; DEFAULT_TYPHOON_ID_LENGTH])
}

fn make_crypto(_settings: &Arc<Settings<DefaultExecutor>>) -> SharedValue<ClientCryptoTool<StaticByteBuffer>> {
    let key_pair = ServerKeyPair::for_tests();
    let identity = test_identity();
    let initial_key = FixedByteBuffer::<32>::from([0u8; 32]);
    let cert = key_pair.to_client_certificate(vec![]);
    SharedValue::new(ClientCryptoTool::new(cert, identity, &initial_key))
}

/// Mock flow manager: returns pre-queued packets in order, then blocks forever.
struct MockFlowManager {
    packets: StdMutex<Vec<DynamicByteBuffer>>,
    /// Counts `send_packet` invocations so drop-path tests can assert behavior.
    send_calls: AtomicUsize,
}

impl MockFlowManager {
    fn new(packets: Vec<DynamicByteBuffer>) -> Arc<Self> {
        Arc::new(Self {
            packets: StdMutex::new(packets),
            send_calls: AtomicUsize::new(0),
        })
    }
}

impl FlowManager for MockFlowManager {
    fn send_packet(&self, _packet: DynamicByteBuffer, _fallthrough: bool, _is_maintenance: bool) -> impl Future<Output = Result<(), FlowControllerError>> {
        self.send_calls.fetch_add(1, Ordering::Relaxed);
        ready(Ok(()))
    }

    async fn receive_packet(&self, _buf: DynamicByteBuffer) -> Result<DynamicByteBuffer, FlowControllerError> {
        let next = {
            let mut lock = self.packets.lock().unwrap();
            if lock.is_empty() {
                None
            } else {
                lock.drain(..1).next()
            }
        };
        match next {
            Some(pkt) => Ok(pkt),
            // Block forever when queue is empty (simulates real socket wait).
            None => std::future::pending().await,
        }
    }
}

/// Assemble a raw packet as the flow layer would deliver it (payload || plaintext trailer).
/// For TERMINATION / health check (no payload), the buffer is just the trailer itself.
fn make_termination_packet(settings: &Arc<Settings<DefaultExecutor>>) -> DynamicByteBuffer {
    let identity = test_identity();
    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    Trailer::termination(buf, &identity, ReturnCode::Success, 0x1234_0000_0000_0001u64).into_buffer()
}

/// Build a `ClientSessionManager` with the given mock flows.
async fn make_session(settings: Arc<Settings<DefaultExecutor>>, flows: Vec<Arc<MockFlowManager>>) -> Arc<ClientSessionManager<StaticByteBuffer, DefaultExecutor, Arc<MockFlowManager>, DefaultClientConnectionHandler>> {
    let cipher = make_crypto(&settings);
    ClientSessionManager::new(cipher, flows, settings, Arc::new(AtomicU32::new(0)), DefaultClientConnectionHandler).expect("ClientSessionManager::new must succeed")
}

// ── receive_packet tests ───────────────────────────────────────────────────────

// Test: TERMINATION packet causes receive_packet to return ConnectionTerminated.
#[tokio::test(flavor = "multi_thread")]
async fn test_receive_packet_termination_returns_error() {
    let settings = fast_settings();
    let termination = make_termination_packet(&settings);
    let flow = MockFlowManager::new(vec![termination]);
    let session = make_session(Arc::clone(&settings), vec![flow]).await;

    let result = session.receive_packet().await;
    assert!(matches!(result, Err(SessionControllerError::ConnectionTerminated(_))), "TERMINATION must yield ConnectionTerminated, got: {result:?}");
}

// Test: with two flows, TERMINATION on one flow still terminates the session.
#[tokio::test(flavor = "multi_thread")]
async fn test_receive_packet_termination_on_any_flow_terminates() {
    let settings = fast_settings();
    let termination = make_termination_packet(&settings);
    // Flow 0 blocks, flow 1 returns TERMINATION immediately.
    let flow0 = MockFlowManager::new(vec![]);
    let flow1 = MockFlowManager::new(vec![termination]);
    let session = make_session(Arc::clone(&settings), vec![flow0, flow1]).await;

    let result = session.receive_packet().await;
    assert!(matches!(result, Err(SessionControllerError::ConnectionTerminated(_))), "TERMINATION on any flow must terminate session, got: {result:?}");
}

// ── send_packet tests ──────────────────────────────────────────────────────────

// Test: send_packet with a zero-length payload does not panic and calls the flow.
#[tokio::test(flavor = "multi_thread")]
async fn test_send_packet_empty_payload_succeeds() {
    let settings = fast_settings();
    let flow = MockFlowManager::new(vec![]);
    let session = make_session(Arc::clone(&settings), vec![flow]).await;

    let buf = settings.pool().allocate(Some(0));
    let result = session.send_packet(buf, false).await;
    assert!(result.is_ok(), "send_packet with empty payload must succeed, got: {result:?}");
}

// Test: send_packet with a non-empty payload succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn test_send_packet_with_payload_succeeds() {
    let settings = fast_settings();
    let flow = MockFlowManager::new(vec![]);
    let session = make_session(Arc::clone(&settings), vec![flow]).await;

    let buf = settings.pool().allocate(Some(16));
    buf.slice_mut().copy_from_slice(b"hello typhoon!!!");
    let result = session.send_packet(buf, false).await;
    assert!(result.is_ok(), "send_packet with payload must succeed, got: {result:?}");
}

// ── Drop-path tests ────────────────────────────────────────────────────────────

// Test: dropping the session drives a TERMINATION send through the single flow.
#[tokio::test(flavor = "multi_thread")]
async fn test_drop_invokes_send_packet() {
    let settings = fast_settings();
    let flow = MockFlowManager::new(vec![]);
    let flow_for_assert = Arc::clone(&flow);
    let session = make_session(Arc::clone(&settings), vec![flow]).await;
    drop(session);
    assert_eq!(flow_for_assert.send_calls.load(Ordering::Relaxed), 1, "drop must invoke send_packet exactly once on the selected flow");
}

// Test: dropping a session with multiple flows still produces exactly one TERMINATION send.
#[tokio::test(flavor = "multi_thread")]
async fn test_drop_sends_termination_on_single_flow_only() {
    let settings = fast_settings();
    let flow0 = MockFlowManager::new(vec![]);
    let flow1 = MockFlowManager::new(vec![]);
    let flow0_assert = Arc::clone(&flow0);
    let flow1_assert = Arc::clone(&flow1);
    let session = make_session(Arc::clone(&settings), vec![flow0, flow1]).await;
    drop(session);
    let total = flow0_assert.send_calls.load(Ordering::Relaxed) + flow1_assert.send_calls.load(Ordering::Relaxed);
    assert_eq!(total, 1, "drop must send TERMINATION on exactly one flow, observed {total}");
}
