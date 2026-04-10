use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::defaults::DefaultExecutor;
use crate::session::server::OutgoingRouter;
use crate::settings::{Settings, SettingsBuilder, keys};
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILOR_LENGTH};
use crate::tailor::{PacketFlags, Tailor};
use crate::bytes::StaticByteBuffer;
use crate::utils::sync::{Mutex, sleep};

use super::ServerHealthProvider;

// ── Test infrastructure ───────────────────────────────────────────────────────

struct CapturingRouter {
    packets: Mutex<Vec<DynamicByteBuffer>>,
    remove_count: AtomicUsize,
}

impl CapturingRouter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            packets: Mutex::new(Vec::new()),
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

fn test_identity() -> StaticByteBuffer {
    StaticByteBuffer::from_slice(&[0u8; DEFAULT_TYPHOON_ID_LENGTH])
}

/// Settings with very short delays for fast tests.
/// Constraints satisfied:
///   TIMEOUT_MIN(5) ≤ TIMEOUT_DEFAULT(10) ≤ TIMEOUT_MAX(20)
///   HEALTH_CHECK_NEXT_IN_MIN(21) > TIMEOUT_MAX(20)
///   HEALTH_CHECK_NEXT_IN_MIN(21) ≤ HEALTH_CHECK_NEXT_IN_MAX(100)
fn fast_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(
        SettingsBuilder::new()
            .set(&keys::TIMEOUT_MIN, 5u64)
            .set(&keys::TIMEOUT_DEFAULT, 10u64)
            .set(&keys::TIMEOUT_MAX, 20u64)
            .set(&keys::HEALTH_CHECK_NEXT_IN_MIN, 21u64)
            .set(&keys::HEALTH_CHECK_NEXT_IN_MAX, 100u64)
            .set(&keys::MAX_RETRIES, 2u64)
            .build()
            .unwrap(),
    )
}

/// Parse PN, TM and flags from the raw buffer emitted by ServerHealthProvider.
/// A health-check response has no body, so the whole buffer is the tailor.
fn parse_response(packet: &DynamicByteBuffer) -> (u64, u32, PacketFlags) {
    let tailor_size = TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH;
    assert!(
        packet.len() >= tailor_size,
        "packet too short: {} < {tailor_size}",
        packet.len()
    );
    let tailor_start = packet.len() - tailor_size;
    let (_, tailor_buf) = packet.split_buf(tailor_start);
    let tailor = Tailor::<StaticByteBuffer>::new(tailor_buf);
    (tailor.packet_number(), tailor.time(), tailor.flags())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// Test: server echoes the client PN in the health-check response. (Bug 1 regression)
#[cfg_attr(feature = "tokio", tokio::test)]
async fn test_server_health_response_echoes_client_pn() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    // Very long initial_server_next_in → timer will not time out during the test.
    let provider = ServerHealthProvider::new(
        Arc::downgrade(&router),
        test_identity(),
        Arc::clone(&settings),
        60_000u32,
    );

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
#[cfg_attr(feature = "tokio", tokio::test)]
async fn test_server_health_response_own_tm_in_range() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let provider = ServerHealthProvider::new(
        Arc::downgrade(&router),
        test_identity(),
        Arc::clone(&settings),
        60_000u32,
    );

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
#[cfg_attr(feature = "tokio", tokio::test)]
async fn test_server_health_response_has_health_check_flag() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let provider = ServerHealthProvider::new(
        Arc::downgrade(&router),
        test_identity(),
        Arc::clone(&settings),
        60_000u32,
    );
    provider.feed_health_check(10u32, 0xABCD);
    sleep(Duration::from_millis(50)).await;
    drop(provider);
    sleep(Duration::from_millis(150)).await;

    let packets = router.packets.lock().await;
    assert_eq!(packets.len(), 1);
    let (_pn, _tm, flags) = parse_response(&packets[0]);
    assert!(flags.contains(PacketFlags::HEALTH_CHECK));
}

// Test: response is not sent before the client's requested delay elapses.
#[cfg_attr(feature = "tokio", tokio::test)]
async fn test_server_health_response_delayed() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let provider = ServerHealthProvider::new(
        Arc::downgrade(&router),
        test_identity(),
        Arc::clone(&settings),
        60_000u32,
    );

    // Request a 100 ms delay (clamped to MAX=100ms).
    provider.feed_health_check(100u32, 0x9999);

    // After 40 ms the response must NOT have arrived yet.
    sleep(Duration::from_millis(40)).await;
    assert_eq!(
        router.packets.lock().await.len(), 0,
        "response must not arrive before client_next_in delay"
    );

    // After another 110 ms (150 ms total) the response has been sent; drop provider
    // now so the task exits cleanly without entering decay retries.
    sleep(Duration::from_millis(110)).await;
    drop(provider);

    // After another 40 ms (190 ms total) the packet must be in the router.
    sleep(Duration::from_millis(40)).await;
    assert_eq!(router.packets.lock().await.len(), 1, "response must arrive after delay");
}

// Test: timer retries on silence and eventually calls remove_session.
#[cfg_attr(feature = "tokio", tokio::test)]
async fn test_server_health_timer_removes_session_after_max_retries() {
    let router = CapturingRouter::new();
    let settings = fast_settings(); // MAX_RETRIES=2, TIMEOUT_DEFAULT=10ms

    // initial_server_next_in = 1 ms → first timeout = 1 + 10 = 11 ms.
    let _provider = ServerHealthProvider::new(
        Arc::downgrade(&router),
        test_identity(),
        Arc::clone(&settings),
        1u32,
    );

    // Never call feed_health_check — let the timer expire MAX_RETRIES times.
    sleep(Duration::from_millis(500)).await;

    assert!(
        router.remove_count.load(Ordering::Relaxed) > 0,
        "session must be removed after max retries"
    );
}

// Test: termination packet is routed before remove_session is called on decay.
#[cfg_attr(feature = "tokio", tokio::test)]
async fn test_server_health_sends_termination_before_remove() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let _provider = ServerHealthProvider::new(
        Arc::downgrade(&router),
        test_identity(),
        Arc::clone(&settings),
        1u32,
    );

    sleep(Duration::from_millis(500)).await;

    assert!(
        !router.packets.lock().await.is_empty(),
        "termination packet must be sent before remove_session"
    );
    assert!(
        router.remove_count.load(Ordering::Relaxed) > 0,
        "remove_session must be called after termination"
    );
}

// Test: dropping the router Arc causes the timer task to stop cleanly.
#[cfg_attr(feature = "tokio", tokio::test)]
async fn test_server_health_stops_when_router_dropped() {
    let router = CapturingRouter::new();
    let settings = fast_settings();

    let provider = ServerHealthProvider::new(
        Arc::downgrade(&router),
        test_identity(),
        Arc::clone(&settings),
        60_000u32,
    );

    drop(router);

    provider.feed_health_check(10u32, 0x1111);

    // Task detects dropped router and exits — no panic expected.
    sleep(Duration::from_millis(100)).await;
}
