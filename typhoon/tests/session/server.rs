use std::sync::Arc;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::bytes::{DynamicByteBuffer, StaticByteBuffer};
use crate::cache::SharedMap;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::certificate::{ObfuscationBufferContainer, ServerKeyPair};
use crate::crypto::{UserCryptoState, UserServerState};
use crate::defaults::DefaultExecutor;
use crate::session::SessionControllerError;
use crate::session::server::{IncomingPacket, OutgoingRouter, ServerSessionManager};
use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use crate::settings::{Settings, SettingsBuilder, keys};
use crate::tailor::{ReturnCode, Tailor};
use crate::utils::sync::create_notify_queue;

/// Shared server secret — generated once so that concurrent tests don't each pay the
/// expensive McEliece key-generation cost.
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
static TEST_SERVER_SECRET: LazyLock<crate::certificate::ServerSecret<'static>> = LazyLock::new(|| ServerKeyPair::for_tests().into_server_secret());

// ── Test infrastructure ───────────────────────────────────────────────────────

fn test_identity() -> StaticByteBuffer {
    StaticByteBuffer::from_slice(&[0u8; DEFAULT_TYPHOON_ID_LENGTH])
}

fn fast_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(SettingsBuilder::new().set(&keys::HEALTH_CHECK_NEXT_IN_MIN, 60_000u64).set(&keys::HEALTH_CHECK_NEXT_IN_MAX, 120_000u64).build().unwrap())
}

/// Minimal outgoing router that records packets and remove_session calls.
struct CapturingRouter {
    packets: crate::utils::sync::Mutex<Vec<DynamicByteBuffer>>,
    remove_count: AtomicUsize,
}

impl CapturingRouter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            packets: crate::utils::sync::Mutex::new(Vec::new()),
            remove_count: AtomicUsize::new(0),
        })
    }
}

impl OutgoingRouter<StaticByteBuffer> for CapturingRouter {
    async fn route_packet(&self, packet: DynamicByteBuffer, _identity: &StaticByteBuffer) -> bool {
        self.packets.lock().await.push(packet);
        true
    }

    async fn remove_session(&self, _identity: &StaticByteBuffer) {
        self.remove_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Build a session using `from_handshake`.
/// Uses a shared static server secret to avoid paying McEliece key-generation cost per test.
async fn make_session(settings: Arc<Settings<DefaultExecutor>>, router: Arc<CapturingRouter>, num_flows: usize) -> Arc<ServerSessionManager<StaticByteBuffer, DefaultExecutor, CapturingRouter>> {
    let identity = test_identity();

    let initial_key = crate::bytes::FixedByteBuffer::<32>::from([0u8; 32]);

    // Build a minimal response body buffer (empty).
    let response_body = settings.pool().allocate(Some(0));

    // Build a synthetic handshake tailor (just need a valid tailor, PN = 1).
    let tailor_buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    let handshake_tailor = Tailor::handshake(tailor_buf, &identity, 0, 1000, 1u64, 0u16);

    let mut users: SharedMap<StaticByteBuffer, UserServerState> = SharedMap::new();
    let (incoming_tx, _incoming_rx) = create_notify_queue::<DynamicByteBuffer>();
    let router_weak = Arc::downgrade(&router);

    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    let (session, _response) = {
        let crypto_state = UserCryptoState::new(&initial_key, TEST_SERVER_SECRET.obfuscation_buffer());
        ServerSessionManager::assemble_session(crypto_state, response_body, handshake_tailor, identity, &mut users, incoming_tx, router_weak, num_flows, settings).await.expect("assemble_session must succeed")
    };

    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    let (session, _response) = {
        let crypto_state = UserCryptoState::new(&initial_key);
        ServerSessionManager::assemble_session(crypto_state, response_body, handshake_tailor, identity, &mut users, incoming_tx, router_weak, num_flows, settings).await.expect("assemble_session must succeed")
    };

    session
}

// ── note_active_flow / select_active_flow ─────────────────────────────────────

// Test: select_active_flow falls back to 0 when no flows have been marked active.
#[tokio::test]
async fn test_select_flow_fallback_when_no_flows_active() {
    let settings = fast_settings();
    let router = CapturingRouter::new();
    let session = make_session(Arc::clone(&settings), Arc::clone(&router), 4).await;

    // No note_active_flow called — should fall back to 0.
    let idx = session.select_active_flow(4);
    assert_eq!(idx, 0, "must fall back to flow 0 when no flows are active");
}

// Test: note_active_flow + select_active_flow returns only marked indices.
#[tokio::test]
async fn test_select_flow_only_from_marked_flows() {
    let settings = fast_settings();
    let router = CapturingRouter::new();
    let session = make_session(Arc::clone(&settings), Arc::clone(&router), 4).await;

    session.note_active_flow(2);
    session.note_active_flow(3);

    // With only flows 2 and 3 active, select must return 2 or 3.
    for _ in 0..50 {
        let idx = session.select_active_flow(4);
        assert!(idx == 2 || idx == 3, "selected flow {idx} is not in the active set {{2, 3}}");
    }
}

// Test: note_active_flow is idempotent — marking the same flow twice changes nothing.
#[tokio::test]
async fn test_note_active_flow_idempotent() {
    let settings = fast_settings();
    let router = CapturingRouter::new();
    let session = make_session(Arc::clone(&settings), Arc::clone(&router), 2).await;

    session.note_active_flow(1);
    session.note_active_flow(1);

    // Must still return 1 (only one flow marked).
    let idx = session.select_active_flow(2);
    assert_eq!(idx, 1, "double-marking flow 1 must not change selection result");
}

// ── process_incoming ──────────────────────────────────────────────────────────

// Test: TERMINATION packet causes process_incoming to return ConnectionTerminated.
#[tokio::test]
async fn test_process_incoming_termination_returns_error() {
    let settings = fast_settings();
    let router = CapturingRouter::new();
    let session = make_session(Arc::clone(&settings), Arc::clone(&router), 1).await;

    let pn: u64 = 0xDEAD_BEEF_0000_0001;
    let identity = test_identity();
    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    let tailor = Tailor::termination(buf, &identity, ReturnCode::Success, pn);
    let body = settings.pool().allocate(Some(0));

    let incoming = IncomingPacket {
        body,
        tailor,
    };
    let result = session.process_incoming(incoming).await;

    assert!(matches!(result, Err(SessionControllerError::ConnectionTerminated(_))), "TERMINATION packet must yield ConnectionTerminated, got: {:?}", result);
}

// Test: health-check-only packet (no payload) is accepted without error.
#[tokio::test]
async fn test_process_incoming_health_check_no_payload() {
    let settings = fast_settings();
    let router = CapturingRouter::new();
    let session = make_session(Arc::clone(&settings), Arc::clone(&router), 1).await;

    let pn: u64 = 0x1111_0000_0000_0002;
    let identity = test_identity();
    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    // health_check produces a tailor with HEALTH_CHECK flag and no payload bit.
    let tailor = Tailor::health_check(buf, &identity, 1000u32, pn);
    let body = settings.pool().allocate(Some(0));

    let incoming = IncomingPacket {
        body,
        tailor,
    };
    let result = session.process_incoming(incoming).await;
    assert!(result.is_ok(), "health-check-only packet must return Ok, got: {result:?}");
}
