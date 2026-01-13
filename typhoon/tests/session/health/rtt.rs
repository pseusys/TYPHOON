use crate::constants::timing::{
    TYPHOON_RTT_DEFAULT, TYPHOON_RTT_MAX, TYPHOON_RTT_MIN, TYPHOON_TIMEOUT_DEFAULT,
    TYPHOON_TIMEOUT_MAX, TYPHOON_TIMEOUT_MIN,
};
use crate::session::health::rtt::RttTracker;

#[test]
fn test_new_tracker_uninitialized() {
    let tracker = RttTracker::new();
    assert!(!tracker.is_initialized());
    assert_eq!(tracker.get_rtt(), TYPHOON_RTT_DEFAULT);
    assert_eq!(tracker.get_timeout(), TYPHOON_TIMEOUT_DEFAULT);
}

#[test]
fn test_first_sample_initializes() {
    let tracker = RttTracker::new();
    tracker.update(2000);

    assert!(tracker.is_initialized());
    assert_eq!(tracker.get_rtt(), 2000);
    assert_eq!(tracker.get_variance(), 1000); // First variance is RTT/2
}

#[test]
fn test_ewma_convergence() {
    let tracker = RttTracker::new();

    // Initialize with 1000ms
    tracker.update(1000);
    assert_eq!(tracker.get_rtt(), 1000);

    // Update with consistent 2000ms samples
    for _ in 0..20 {
        tracker.update(2000);
    }

    // Should converge toward 2000ms
    let rtt = tracker.get_rtt();
    assert!(rtt > 1500, "RTT should converge toward 2000, got {}", rtt);
}

#[test]
fn test_rtt_clamping() {
    let tracker = RttTracker::new();

    // Very low RTT should be clamped
    tracker.update(100);
    assert!(tracker.get_rtt() >= TYPHOON_RTT_MIN);

    // Very high RTT should be clamped
    tracker.reset();
    tracker.update(100000);
    assert!(tracker.get_rtt() <= TYPHOON_RTT_MAX);
}

#[test]
fn test_timeout_calculation() {
    let tracker = RttTracker::new();
    tracker.update(2000);

    let timeout = tracker.get_timeout();
    // Timeout = (srtt + rttvar) * factor = (2000 + 1000) * 5 = 15000
    // But clamped to TYPHOON_TIMEOUT_MAX
    assert!(timeout >= TYPHOON_TIMEOUT_MIN);
    assert!(timeout <= TYPHOON_TIMEOUT_MAX);
}

#[test]
fn test_reset() {
    let tracker = RttTracker::new();
    tracker.update(3000);
    assert!(tracker.is_initialized());

    tracker.reset();
    assert!(!tracker.is_initialized());
    assert_eq!(tracker.get_rtt(), TYPHOON_RTT_DEFAULT);
}

#[test]
fn test_clone() {
    let tracker = RttTracker::new();
    tracker.update(2500);

    let cloned = tracker.clone();
    assert_eq!(cloned.get_rtt(), tracker.get_rtt());
    assert_eq!(cloned.get_variance(), tracker.get_variance());
    assert_eq!(cloned.is_initialized(), tracker.is_initialized());
}

#[test]
fn test_variance_decreases_with_stable_rtt() {
    let tracker = RttTracker::new();

    // Initialize
    tracker.update(2000);
    let initial_variance = tracker.get_variance();

    // Multiple consistent samples should reduce variance
    for _ in 0..10 {
        tracker.update(2000);
    }

    let final_variance = tracker.get_variance();
    assert!(
        final_variance < initial_variance,
        "Variance should decrease: {} < {}",
        final_variance,
        initial_variance
    );
}
