use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use std::sync::LazyLock;

use crate::bytes::{DynamicByteBuffer, StaticByteBuffer};
use crate::cache::SharedValue;
use crate::bytes::FixedByteBuffer;
use crate::certificate::ServerKeyPair;
use crate::crypto::ClientCryptoTool;
use crate::defaults::{DefaultClientConnectionHandler, DefaultExecutor};
use crate::session::SessionControllerError;
use crate::session::common::SessionManager;
use crate::settings::{Settings, SettingsBuilder, keys};
use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use crate::tailor::{PacketFlags, Tailor};
use crate::utils::sync::{create_watch, WatchReceiver};

use super::{ClientHealthProvider, HealthState};

// ── Cached test key material (McEliece keygen is expensive) ──────────────────

static TEST_KEY_PAIR: LazyLock<ServerKeyPair> = LazyLock::new(ServerKeyPair::for_tests);

// ── Test infrastructure ───────────────────────────────────────────────────────

fn test_identity() -> StaticByteBuffer {
    StaticByteBuffer::from_slice(&[0u8; DEFAULT_TYPHOON_ID_LENGTH])
}

fn make_test_crypto_tool() -> SharedValue<ClientCryptoTool<StaticByteBuffer>> {
    let identity = test_identity();
    let initial_key = FixedByteBuffer::<32>::from([0u8; 32]);
    let cert = TEST_KEY_PAIR.to_client_certificate(vec![]);
    SharedValue::new(ClientCryptoTool::new(cert, identity, &initial_key))
}

fn fast_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(
        SettingsBuilder::new()
            .set(&keys::TIMEOUT_MIN, 5u64)
            .set(&keys::TIMEOUT_DEFAULT, 10u64)
            .set(&keys::TIMEOUT_MAX, 20u64)
            .set(&keys::HEALTH_CHECK_NEXT_IN_MIN, 21u64)
            .set(&keys::HEALTH_CHECK_NEXT_IN_MAX, 100u64)
            .set(&keys::MAX_RETRIES, 3u64)
            .build()
            .unwrap(),
    )
}

/// Minimal session manager that records sent packets and can optionally fail.
struct MockSessionManager {
    sent: StdMutex<Vec<DynamicByteBuffer>>,
    fail: bool,
}

impl MockSessionManager {
    fn new() -> Arc<Self> {
        Arc::new(Self { sent: StdMutex::new(vec![]), fail: false })
    }

    #[allow(dead_code)]
    fn failing() -> Arc<Self> {
        Arc::new(Self { sent: StdMutex::new(vec![]), fail: true })
    }
}

impl SessionManager for MockSessionManager {
    async fn send_packet(&self, packet: DynamicByteBuffer, _generated: bool) -> Result<(), SessionControllerError> {
        if self.fail {
            return Err(SessionControllerError::HealthProviderDied);
        }
        self.sent.lock().unwrap().push(packet);
        Ok(())
    }

    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        Err(SessionControllerError::HealthProviderDied)
    }
}

type TestHealthResponse = (u32, u128, Option<DynamicByteBuffer>, Option<StaticByteBuffer>);

/// Build a ClientHealthProvider and return it together with the shadowride receiver.
/// Tests that need to observe the response channel call `provider.response_tx.subscribe()`.
fn make_provider(
    mgr: Arc<MockSessionManager>,
    settings: Arc<Settings<DefaultExecutor>>,
) -> (
    ClientHealthProvider<StaticByteBuffer, DefaultExecutor, MockSessionManager, DefaultClientConnectionHandler>,
    WatchReceiver<()>,
) {
    let crypto = make_test_crypto_tool();
    let (response_tx, response_rx) = create_watch::<TestHealthResponse>();
    let (shadowride_tx, shadowride_rx) = create_watch::<()>();
    let provider = ClientHealthProvider::new(
        Arc::downgrade(&mgr),
        settings,
        crypto,
        response_tx,
        shadowride_tx,
        response_rx,
        DefaultClientConnectionHandler,
    );
    (provider, shadowride_rx)
}

// ── HealthState pure-logic tests ─────────────────────────────────────────────

// Test: compute_next_in always returns a value within the configured [MIN, MAX] range.
#[tokio::test]
async fn test_health_state_compute_next_in_in_range() {
    let settings = fast_settings();
    let (response_tx, response_rx) = create_watch::<TestHealthResponse>();
    let (shadowride_tx, _) = create_watch::<()>();
    let _ = shadowride_tx;

    let crypto = make_test_crypto_tool();
    let state = HealthState::new(
        Arc::clone(&settings),
        crypto,
        DefaultClientConnectionHandler,
        response_rx,
    );
    let _ = response_tx;

    let min = settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN) as u32;
    let max = settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX) as u32;
    for _ in 0..50 {
        let next_in = state.compute_next_in();
        assert!(
            next_in >= min && next_in <= max,
            "compute_next_in returned {next_in}, expected [{min}, {max}]"
        );
    }
}

// Test: compute_timeout with no RTT uses the configured default.
#[tokio::test]
async fn test_health_state_compute_timeout_default() {
    let settings = fast_settings();
    let (_, response_rx) = create_watch::<TestHealthResponse>();
    let crypto = make_test_crypto_tool();
    let state = HealthState::new(Arc::clone(&settings), crypto, DefaultClientConnectionHandler, response_rx);

    let timeout = state.compute_timeout();
    let min = settings.get(&keys::TIMEOUT_MIN);
    let max = settings.get(&keys::TIMEOUT_MAX);
    assert!(timeout >= min && timeout <= max, "timeout {timeout} not in [{min}, {max}]");
}

// Test: compute_timeout with RTT returns a value based on srtt + rttvar.
#[tokio::test]
async fn test_health_state_compute_timeout_with_rtt() {
    let settings = fast_settings();
    let (_, response_rx) = create_watch::<TestHealthResponse>();
    let crypto = make_test_crypto_tool();
    let mut state = HealthState::new(Arc::clone(&settings), crypto, DefaultClientConnectionHandler, response_rx);

    state.smooth_rtt = Some(5.0);
    state.rtt_variance = Some(2.0);

    let timeout = state.compute_timeout();
    let min = settings.get(&keys::TIMEOUT_MIN);
    let max = settings.get(&keys::TIMEOUT_MAX);
    // (5 + 2) * factor — whatever the factor, must be clamped to [min, max].
    assert!(timeout >= min && timeout <= max, "rtt-derived timeout {timeout} not in [{min}, {max}]");
}

// Test: increment_retry returns true while below MAX_RETRIES, false at the limit.
#[tokio::test]
async fn test_health_state_increment_retry() {
    let settings = fast_settings(); // MAX_RETRIES = 3
    let (_, response_rx) = create_watch::<TestHealthResponse>();
    let crypto = make_test_crypto_tool();
    let mut state = HealthState::new(Arc::clone(&settings), crypto, DefaultClientConnectionHandler, response_rx);

    assert!(state.increment_retry(), "retry 1 should be under limit");
    assert!(state.increment_retry(), "retry 2 should be under limit");
    assert!(!state.increment_retry(), "retry 3 should hit MAX_RETRIES=3");
}

// Test: update_rtt initialises smooth_rtt and rtt_variance on the first measurement.
#[tokio::test]
async fn test_health_state_rtt_first_measurement() {
    let settings = fast_settings();
    let (_, response_rx) = create_watch::<TestHealthResponse>();
    let crypto = make_test_crypto_tool();
    let mut state = HealthState::new(Arc::clone(&settings), crypto, DefaultClientConnectionHandler, response_rx);

    state.last_sent_time = 0;
    state.last_sent_next_in = 0;
    let receive_time: u128 = 50; // RTT = 50 - 0 - 0 = 50, clamped

    state.update_rtt(receive_time);

    assert!(state.smooth_rtt.is_some(), "smooth_rtt must be initialised");
    assert!(state.rtt_variance.is_some(), "rtt_variance must be initialised");
    // rtt_variance should be approximately smooth_rtt / 2.
    let srtt = state.smooth_rtt.unwrap();
    let rttvar = state.rtt_variance.unwrap();
    assert!(
        (rttvar - srtt / 2.0).abs() < 1.0,
        "initial rttvar should be srtt/2, got srtt={srtt}, rttvar={rttvar}"
    );
}

// Test: update_rtt converges smooth_rtt toward repeated measurements.
#[tokio::test]
async fn test_health_state_rtt_ewma_converges() {
    let settings = fast_settings();
    let (_, response_rx) = create_watch::<TestHealthResponse>();
    let crypto = make_test_crypto_tool();
    let mut state = HealthState::new(Arc::clone(&settings), crypto, DefaultClientConnectionHandler, response_rx);

    state.last_sent_time = 0;
    state.last_sent_next_in = 0;

    // Feed 20 identical samples of RTT_MIN (clamped floor) ms.
    let rtt_min = settings.get(&keys::RTT_MIN) as f64;
    for i in 0..20 {
        let _ = i;
        state.last_sent_time = 0;
        state.last_sent_next_in = 0;
        state.update_rtt(rtt_min as u128);
    }

    let srtt = state.smooth_rtt.unwrap();
    // After many identical samples the EWMA should be near rtt_min.
    assert!(
        (srtt - rtt_min).abs() < rtt_min * 0.1,
        "EWMA should converge near {rtt_min}ms, got {srtt}ms"
    );
}

// ── ClientHealthProvider::feed_input tests ────────────────────────────────────

// Test: feed_input with mismatched PN is silently discarded (no response sent).
#[tokio::test]
async fn test_feed_input_wrong_pn_discarded() {
    let mgr = MockSessionManager::new();
    let settings = fast_settings();
    let (provider, _) = make_provider(Arc::clone(&mgr), Arc::clone(&settings));

    // Set current_pn = 100; feed a tailor with PN = 99.
    provider.state.lock().await.current_pn = 100;

    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    let tailor = Tailor::health_check(buf, &test_identity(), 50u32, 99u64);

    provider.feed_input(tailor).await.unwrap();

    // The watch channel has no pending value — try receiving with a timeout.
    let mut rx = provider.response_tx.subscribe();
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        rx.recv(),
    ).await;
    assert!(result.is_err(), "no response must be sent for wrong PN");
}

// Test: feed_input with correct PN delivers to the response channel.
#[tokio::test]
async fn test_feed_input_correct_pn_delivers() {
    let mgr = MockSessionManager::new();
    let settings = fast_settings();
    let (provider, _) = make_provider(Arc::clone(&mgr), Arc::clone(&settings));

    let pn: u64 = 0xABCD_0000_0000_0001;
    provider.state.lock().await.current_pn = pn;

    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    let server_tm: u32 = 50; // within [21, 100]
    let tailor = Tailor::health_check(buf, &test_identity(), server_tm, pn);

    // Subscribe before feeding so we don't miss the send.
    let mut rx = provider.response_tx.subscribe();
    provider.feed_input(tailor).await.unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        rx.recv(),
    )
    .await
    .expect("response must arrive")
    .expect("channel must not be closed");

    let (received_tm, _time, body, _identity) = result;
    assert_eq!(received_tm, server_tm, "received TM must match tailor TM");
    assert!(body.is_none(), "standalone health check has no body");
}

// Test: feed_input clamps the TM to configured [MIN, MAX].
#[tokio::test]
async fn test_feed_input_tm_clamped() {
    let mgr = MockSessionManager::new();
    let settings = fast_settings();
    let (provider, _) = make_provider(Arc::clone(&mgr), Arc::clone(&settings));

    let pn: u64 = 0x1111_0000_0000_0001;
    provider.state.lock().await.current_pn = pn;

    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    // Use TM = 0 (below HEALTH_CHECK_NEXT_IN_MIN = 21).
    let tailor = Tailor::health_check(buf, &test_identity(), 0u32, pn);

    let mut rx = provider.response_tx.subscribe();
    provider.feed_input(tailor).await.unwrap();

    let (received_tm, _, _, _) = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        rx.recv(),
    )
    .await
    .unwrap()
    .unwrap();

    let min = settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN) as u32;
    assert_eq!(received_tm, min, "TM=0 must be clamped to MIN={min}");
}

// ── ClientHealthProvider::feed_output / shadowride tests ─────────────────────

// Test: feed_output is a no-op when a packet already has the HEALTH_CHECK flag.
#[tokio::test]
async fn test_feed_output_noop_when_already_health_check() {
    let mgr = MockSessionManager::new();
    let settings = fast_settings();
    let (provider, mut shadowride_rx) = make_provider(Arc::clone(&mgr), Arc::clone(&settings));

    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    // A packet that already carries HEALTH_CHECK (e.g., standalone or shadowride).
    let tailor = Tailor::health_check(buf, &test_identity(), 50u32, 0x1234);

    provider.feed_output(tailor).await.unwrap();

    // Shadowride channel must NOT have been signalled.
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        shadowride_rx.recv(),
    )
    .await;
    assert!(result.is_err(), "shadowride_tx must not fire when packet already has HC flag");
}

// Test: feed_output is a no-op when shadowride_pending is None.
#[tokio::test]
async fn test_feed_output_noop_when_nothing_pending() {
    let mgr = MockSessionManager::new();
    let settings = fast_settings();
    let (provider, mut shadowride_rx) = make_provider(Arc::clone(&mgr), Arc::clone(&settings));

    // Ensure nothing is pending.
    provider.state.lock().await.shadowride_pending = None;

    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    let tailor = Tailor::data(buf, &test_identity(), 0u16, 0u64);

    provider.feed_output(tailor).await.unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        shadowride_rx.recv(),
    )
    .await;
    assert!(result.is_err(), "no shadowride signal when nothing pending");
}

// Test: feed_output attaches the pending health check to a DATA packet.
#[tokio::test]
async fn test_feed_output_attaches_shadowride() {
    let mgr = MockSessionManager::new();
    let settings = fast_settings();
    let (provider, mut shadowride_rx) = make_provider(Arc::clone(&mgr), Arc::clone(&settings));

    let pn: u64 = 0xCAFE_0000_0000_BABE;
    let next_in: u32 = 42;
    provider.state.lock().await.shadowride_pending = Some((pn, next_in));

    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    let tailor = Tailor::data(buf.clone(), &test_identity(), 0u16, 0u64);

    provider.feed_output(tailor.clone()).await.unwrap();

    // Shadowride channel must have been signalled.
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        shadowride_rx.recv(),
    )
    .await;
    assert!(result.is_ok(), "shadowride_tx must fire after attachment");

    // The tailor flags must now include HEALTH_CHECK.
    assert!(
        tailor.flags().contains(PacketFlags::HEALTH_CHECK),
        "tailor must carry HEALTH_CHECK flag after shadowride"
    );
    // The tailor TM and PN must have been updated.
    assert_eq!(tailor.time(), next_in, "tailor TM must be set to next_in");
    assert_eq!(tailor.packet_number(), pn, "tailor PN must be set to pending pn");
}

// Test: after feed_output attaches a shadowride, shadowride_pending is cleared.
#[tokio::test]
async fn test_feed_output_clears_pending_after_attach() {
    let mgr = MockSessionManager::new();
    let settings = fast_settings();
    let (provider, _shadowride_rx) = make_provider(Arc::clone(&mgr), Arc::clone(&settings));

    provider.state.lock().await.shadowride_pending = Some((1u64, 10u32));

    let buf = settings.pool().allocate(Some(DEFAULT_TYPHOON_ID_LENGTH));
    let tailor = Tailor::data(buf, &test_identity(), 0u16, 0u64);

    provider.feed_output(tailor).await.unwrap();

    assert!(
        provider.state.lock().await.shadowride_pending.is_none(),
        "shadowride_pending must be cleared after attachment"
    );
}
