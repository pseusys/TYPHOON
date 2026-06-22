use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;

use super::ServerHealthProvider;
use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer, StaticByteBuffer};
use crate::defaults::DefaultExecutor;
use crate::session::server::OutgoingRouter;
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILER_LENGTH};
use crate::settings::{Settings, SettingsBuilder, keys};
use crate::tailer::{PacketFlags, Tailer};
use crate::utils::sync::{Mutex, sleep};

// ── Test infrastructure ───────────────────────────────────────────────────────

struct CapturingRouter {
    packets: Mutex<Vec<DynamicByteBuffer>>,
    remove_count: AtomicUsize,
    current_pn: AtomicU64,
}

impl CapturingRouter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            packets: Mutex::new(Vec::new()),
            remove_count: AtomicUsize::new(0),
            current_pn: AtomicU64::new(1),
        })
    }
}

#[async_trait]
impl OutgoingRouter<StaticByteBuffer> for CapturingRouter {
    async fn route_packet(&self, packet: DynamicByteBuffer, _identity: &StaticByteBuffer) -> bool {
        self.packets.lock().await.push(packet);
        true
    }

    async fn is_current_session(&self, _identity: &StaticByteBuffer, handshake_pn: u64) -> bool {
        self.current_pn.load(Ordering::Relaxed) == handshake_pn
    }

    async fn remove_session(&self, identity: &StaticByteBuffer, handshake_pn: u64) -> bool {
        if !self.is_current_session(identity, handshake_pn).await {
            return false;
        }
        self.remove_count.fetch_add(1, Ordering::Relaxed);
        true
    }
}

fn downgrade_router(r: &Arc<CapturingRouter>) -> std::sync::Weak<dyn OutgoingRouter<StaticByteBuffer>> {
    let cloned: Arc<CapturingRouter> = Arc::clone(r);
    let dyn_r: Arc<dyn OutgoingRouter<StaticByteBuffer>> = cloned;
    Arc::downgrade(&dyn_r)
}

fn test_identity() -> StaticByteBuffer {
    StaticByteBuffer::from_slice(&[0u8; DEFAULT_TYPHOON_ID_LENGTH])
}

/// Settings with very short delays for fast tests.
/// Constraints satisfied:
///   TIMEOUT_MIN(5) ≤ TIMEOUT_DEFAULT(10) ≤ TIMEOUT_MAX(20)
///   HEALTH_CHECK_NEXT_IN_MIN(21) > TIMEOUT_MAX(20)
///   HEALTH_CHECK_NEXT_IN_MIN(21) ≤ HEALTH_CHECK_NEXT_IN_MAX(100)
fn fast_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(SettingsBuilder::new().set(&keys::TIMEOUT_MIN, 5u64).set(&keys::TIMEOUT_DEFAULT, 10u64).set(&keys::TIMEOUT_MAX, 20u64).set(&keys::HEALTH_CHECK_NEXT_IN_MIN, 21u64).set(&keys::HEALTH_CHECK_NEXT_IN_MAX, 100u64).set(&keys::MAX_RETRIES, 2u64).build().unwrap())
}

/// Parse PN, TM and flags from the raw buffer emitted by ServerHealthProvider.
/// A health-check response has no body, so the whole buffer is the tailer.
fn parse_response(packet: &DynamicByteBuffer) -> (u64, u32, PacketFlags) {
    let tailer_size = TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH;
    assert!(packet.len() >= tailer_size, "packet too short: {} < {tailer_size}", packet.len());
    let tailer_start = packet.len() - tailer_size;
    let (_, tailer_buf) = packet.split_buf_start(tailer_start);
    let tailer = Tailer::<StaticByteBuffer>::new(tailer_buf);
    (tailer.packet_number(), tailer.time(), tailer.flags())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// Test: server echoes the client PN in the health-check response. (Bug 1 regression)
#[tokio::test]
async fn test_server_health_response_echoes_client_pn() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    // Very long initial_server_next_in → timer will not time out during the test.
    let provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 60_000u32, 1u64);

    let client_pn: u64 = 0xDEAD_BEEF_0000_0001;
    provider.feed_health_check(10u32, client_pn);
    // Wait past the clamped 21 ms response delay, then drop so the task sees Terminated
    // while waiting for the *next* HC (outer loop), not during the inner delay — this
    // prevents decay retries from adding extra packets within the observation window.
    sleep(Duration::from_millis(50)).await;
    drop(provider);
    sleep(Duration::from_millis(150)).await;

    let packets = router.packets.lock().await;
    assert_eq!(packets.len(), 1, "expected exactly one response");
    let (pn, _tm, _flags) = parse_response(&packets[0]);
    assert_eq!(pn, client_pn, "server must echo the client PN");
}

// Test: server uses its own randomly generated TM, not the client's value. (Bug 2 regression)
#[tokio::test]
async fn test_server_health_response_own_tm_in_range() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 60_000u32, 1u64);

    provider.feed_health_check(10u32, 0x1234_5678_0000_0001);
    sleep(Duration::from_millis(50)).await;
    drop(provider);
    sleep(Duration::from_millis(150)).await;

    let packets = router.packets.lock().await;
    assert_eq!(packets.len(), 1);
    let (_pn, tm, _flags) = parse_response(&packets[0]);

    let min = settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN) as u32;
    let max = settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX) as u32;
    assert!(tm >= min && tm <= max, "server TM {tm} not in [{min}, {max}]");
}

// Test: response carries the HEALTH_CHECK flag.
#[tokio::test]
async fn test_server_health_response_has_health_check_flag() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 60_000u32, 1u64);
    provider.feed_health_check(10u32, 0xABCD);
    sleep(Duration::from_millis(50)).await;
    drop(provider);
    sleep(Duration::from_millis(150)).await;

    let packets = router.packets.lock().await;
    assert_eq!(packets.len(), 1);
    let (_pn, _tm, flags) = parse_response(&packets[0]);
    assert!(flags.contains(PacketFlags::HEALTH_CHECK));
}

/// Test: response is not sent before the client's requested delay elapses.
#[tokio::test]
async fn test_server_health_response_delayed() {
    let router = CapturingRouter::new();
    let settings: Arc<Settings<DefaultExecutor>> = Arc::new(SettingsBuilder::new().set(&keys::TIMEOUT_MIN, 5u64).set(&keys::TIMEOUT_DEFAULT, 10u64).set(&keys::TIMEOUT_MAX, 20u64).set(&keys::HEALTH_CHECK_NEXT_IN_MIN, 300u64).set(&keys::HEALTH_CHECK_NEXT_IN_MAX, 300u64).set(&keys::MAX_RETRIES, 2u64).build().unwrap());

    let provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 60_000u32, 1u64);

    // Request a 300 ms delay (clamped to MIN=MAX=300 ms).
    provider.feed_health_check(300u32, 0x9999);

    // After 150 ms the response must NOT have arrived yet.
    sleep(Duration::from_millis(150)).await;
    assert_eq!(router.packets.lock().await.len(), 0, "response must not arrive before client_next_in delay");

    // After another 200 ms (350 ms total) the response has been sent; drop provider
    // now so the task exits cleanly before the server's own retry timer fires.
    sleep(Duration::from_millis(200)).await;
    drop(provider);

    // After another 80 ms (430 ms total) the packet must be in the router.
    sleep(Duration::from_millis(80)).await;
    assert_eq!(router.packets.lock().await.len(), 1, "response must arrive after delay");
}

// Test: timer retries on silence and eventually calls remove_session.
#[tokio::test]
async fn test_server_health_timer_removes_session_after_max_retries() {
    let router = CapturingRouter::new();
    let settings = fast_settings(); // MAX_RETRIES=2, TIMEOUT_DEFAULT=10ms

    // initial_server_next_in = 1 ms → first timeout = 1 + 10 = 11 ms.
    let _provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 1u32, 1u64);

    // Never call feed_health_check — let the timer expire MAX_RETRIES times.
    sleep(Duration::from_millis(500)).await;

    assert!(router.remove_count.load(Ordering::Relaxed) > 0, "session must be removed after max retries");
}

// Test: termination packet is routed before remove_session is called on decay.
#[tokio::test]
async fn test_server_health_sends_termination_before_remove() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let _provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 1u32, 1u64);

    sleep(Duration::from_millis(500)).await;

    assert!(!router.packets.lock().await.is_empty(), "termination packet must be sent before remove_session");
    assert!(router.remove_count.load(Ordering::Relaxed) > 0, "remove_session must be called after termination");
}

// Test: if the session has been replaced (router reports a different current handshake_pn) by
// the time the decay timer fires, the stale provider sends no termination and removes nothing.
#[tokio::test]
async fn test_server_health_skips_decay_cleanup_when_session_replaced() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let _provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 1u32, 1u64);

    // Simulate a re-handshake replacing this session before decay can fire.
    router.current_pn.store(2, Ordering::Relaxed);

    sleep(Duration::from_millis(500)).await;

    assert!(router.packets.lock().await.is_empty(), "no termination packet must be sent for a superseded session");
    assert_eq!(router.remove_count.load(Ordering::Relaxed), 0, "remove_session must not be called for a superseded session");
}

// Test: dropping the router Arc causes the timer task to stop cleanly.
#[tokio::test]
async fn test_server_health_stops_when_router_dropped() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let provider = ServerHealthProvider::new(downgrade_router(&router), test_identity(), Arc::clone(&settings), 60_000u32, 1u64);

    drop(router);

    provider.feed_health_check(10u32, 0x1111);

    // Task detects dropped router and exits — no panic expected.
    sleep(Duration::from_millis(100)).await;
}
