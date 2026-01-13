use std::sync::Arc;

use crate::constants::timing::{
    TYPHOON_HEALTH_CHECK_NEXT_IN_MAX, TYPHOON_HEALTH_CHECK_NEXT_IN_MIN, TYPHOON_MAX_RETRIES,
};
use crate::session::health::decay::{DecayCycle, DecayState};
use crate::session::health::rtt::RttTracker;

#[test]
fn test_decay_state_initial() {
    let rtt = Arc::new(RttTracker::new());
    let (cycle, _, _) = DecayCycle::new(rtt);
    assert_eq!(cycle.state(), DecayState::Handshaking);
    assert!(cycle.is_active());
}

#[test]
fn test_handshake_complete() {
    let rtt = Arc::new(RttTracker::new());
    let (cycle, _, _) = DecayCycle::new(rtt);

    cycle.handshake_complete();
    assert_eq!(cycle.state(), DecayState::Idle);
}

#[test]
fn test_generate_next_in_bounds() {
    for _ in 0..100 {
        let next_in = DecayCycle::generate_next_in();
        assert!(next_in >= TYPHOON_HEALTH_CHECK_NEXT_IN_MIN);
        assert!(next_in <= TYPHOON_HEALTH_CHECK_NEXT_IN_MAX);
    }
}

#[test]
fn test_clamp_next_in() {
    assert_eq!(
        DecayCycle::clamp_next_in(0),
        TYPHOON_HEALTH_CHECK_NEXT_IN_MIN
    );
    assert_eq!(
        DecayCycle::clamp_next_in(u32::MAX),
        TYPHOON_HEALTH_CHECK_NEXT_IN_MAX
    );
    assert_eq!(DecayCycle::clamp_next_in(100000), 100000);
}

#[test]
fn test_handle_timeout_increments_retry() {
    let rtt = Arc::new(RttTracker::new());
    let (cycle, _, _) = DecayCycle::new(rtt);

    for i in 0..(TYPHOON_MAX_RETRIES - 1) {
        let failed = cycle.handle_timeout();
        assert!(!failed);
        assert_eq!(cycle.retry_count(), i + 1);
    }

    // Last retry should fail
    let failed = cycle.handle_timeout();
    assert!(failed);
    assert_eq!(cycle.state(), DecayState::Failed);
}

#[test]
fn test_process_health_check_resets_retry() {
    let rtt = Arc::new(RttTracker::new());
    let (cycle, _, _) = DecayCycle::new(rtt);

    cycle.handshake_complete();
    cycle.handle_timeout();
    cycle.handle_timeout();
    assert_eq!(cycle.retry_count(), 2);

    cycle.prepare_send(12345);
    cycle.process_health_check(12345, 100000);
    assert_eq!(cycle.retry_count(), 0);
    assert_eq!(cycle.state(), DecayState::Idle);
}

#[test]
fn test_terminate() {
    let rtt = Arc::new(RttTracker::new());
    let (cycle, _, _) = DecayCycle::new(rtt);

    cycle.terminate();
    assert_eq!(cycle.state(), DecayState::Terminated);
    assert!(!cycle.is_active());
}
