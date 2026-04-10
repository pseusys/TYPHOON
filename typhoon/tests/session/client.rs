use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use crate::bytes::{ByteBufferMut, DynamicByteBuffer, FixedByteBuffer, StaticByteBuffer};
use crate::cache::SharedValue;
use crate::certificate::ServerKeyPair;
use crate::crypto::ClientCryptoTool;
use crate::flow::{FlowControllerError, FlowManager};
use crate::defaults::DefaultClientConnectionHandler;
use crate::defaults::DefaultExecutor;
use crate::session::SessionControllerError;
use crate::session::common::SessionManager;
use crate::session::client::ClientSessionManager;
use crate::settings::{Settings, SettingsBuilder, keys};
use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use crate::tailor::{ReturnCode, Tailor};

// ── Test infrastructure ───────────────────────────────────────────────────────

fn fast_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(
        SettingsBuilder::new()
            .set(&keys::HEALTH_CHECK_NEXT_IN_MIN, 60_000u64)
            .set(&keys::HEALTH_CHECK_NEXT_IN_MAX, 120_000u64)
            .build()
            .unwrap(),
    )
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
}

impl MockFlowManager {
    fn new(packets: Vec<DynamicByteBuffer>) -> Arc<Self> {
        Arc::new(Self { packets: StdMutex::new(packets) })
    }
}

impl FlowManager for MockFlowManager {
    async fn send_packet(&self, _packet: DynamicByteBuffer, _generated: bool) -> Result<(), FlowControllerError> {
        Ok(())
    }

    async fn receive_packet(&self, _buf: DynamicByteBuffer) -> Result<DynamicByteBuffer, FlowControllerError> {
        let next = {
            let mut lock = self.packets.lock().unwrap();
            if lock.is_empty() { None } else { lock.drain(..1).next() }
        };
        match next {
            Some(pkt) => Ok(pkt),
            // Block forever when queue is empty (simulates real socket wait).
            None => std::future::pending().await,
        }
    }
}

/// Assemble a raw packet as the flow layer would deliver it (payload || plaintext tailor).
/// For TERMINATION / health check (no payload), the buffer is just the tailor itself.
fn make_termination_packet(settings: &Arc<Settings<DefaultExecutor>>) -> DynamicByteBuffer {
    let identity = test_identity();
    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    Tailor::termination(buf, &identity, ReturnCode::Success, 0x1234_0000_0000_0001u64).into_buffer()
}

/// Build a `ClientSessionManager` with the given mock flows.
async fn make_session(
    settings: Arc<Settings<DefaultExecutor>>,
    flows: Vec<Arc<MockFlowManager>>,
) -> Arc<ClientSessionManager<StaticByteBuffer, DefaultExecutor, Arc<MockFlowManager>, DefaultClientConnectionHandler>> {
    let cipher = make_crypto(&settings);
    ClientSessionManager::new(cipher, flows, settings, DefaultClientConnectionHandler)
        .expect("ClientSessionManager::new must succeed")
}

// ── receive_packet tests ───────────────────────────────────────────────────────

// Test: TERMINATION packet causes receive_packet to return ConnectionTerminated.
#[tokio::test]
async fn test_receive_packet_termination_returns_error() {
    let settings = fast_settings();
    let termination = make_termination_packet(&settings);
    let flow = MockFlowManager::new(vec![termination]);
    let session = make_session(Arc::clone(&settings), vec![flow]).await;

    let result = session.receive_packet().await;
    assert!(
        matches!(result, Err(SessionControllerError::ConnectionTerminated(_))),
        "TERMINATION must yield ConnectionTerminated, got: {:?}", result
    );
}

// Test: with two flows, TERMINATION on one flow still terminates the session.
#[tokio::test]
async fn test_receive_packet_termination_on_any_flow_terminates() {
    let settings = fast_settings();
    let termination = make_termination_packet(&settings);
    // Flow 0 blocks, flow 1 returns TERMINATION immediately.
    let flow0 = MockFlowManager::new(vec![]);
    let flow1 = MockFlowManager::new(vec![termination]);
    let session = make_session(Arc::clone(&settings), vec![flow0, flow1]).await;

    let result = session.receive_packet().await;
    assert!(
        matches!(result, Err(SessionControllerError::ConnectionTerminated(_))),
        "TERMINATION on any flow must terminate session, got: {:?}", result
    );
}

// ── send_packet tests ──────────────────────────────────────────────────────────

// Test: send_packet with a zero-length payload does not panic and calls the flow.
#[tokio::test]
async fn test_send_packet_empty_payload_succeeds() {
    let settings = fast_settings();
    let flow = MockFlowManager::new(vec![]);
    let session = make_session(Arc::clone(&settings), vec![flow]).await;

    let buf = settings.pool().allocate(Some(0));
    let result = session.send_packet(buf, false).await;
    assert!(result.is_ok(), "send_packet with empty payload must succeed, got: {:?}", result);
}

// Test: send_packet with a non-empty payload succeeds.
#[tokio::test]
async fn test_send_packet_with_payload_succeeds() {
    let settings = fast_settings();
    let flow = MockFlowManager::new(vec![]);
    let session = make_session(Arc::clone(&settings), vec![flow]).await;

    let buf = settings.pool().allocate(Some(16));
    buf.slice_mut().copy_from_slice(b"hello typhoon!!!");
    let result = session.send_packet(buf, false).await;
    assert!(result.is_ok(), "send_packet with payload must succeed, got: {:?}", result);
}
