use std::thread::sleep;
use std::time::Duration;

use crate::constants::decoy::TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT;
use crate::flow::decoy::rate_tracker::RateTracker;

#[test]
fn test_new_tracker() {
    let tracker = RateTracker::new();
    assert!(!tracker.is_burst());
    assert!(tracker.time_since_last_packet_ms().is_none());
}

#[test]
fn test_record_packet() {
    let tracker = RateTracker::new();

    tracker.record_packet(100);
    assert!(tracker.time_since_last_packet_ms().is_some());

    sleep(Duration::from_millis(10));
    tracker.record_packet(100);

    // Rate should have updated
    let rate = tracker.current_packet_rate_ms();
    assert!(rate > 0.0);
}

#[test]
fn test_reset() {
    let tracker = RateTracker::new();
    tracker.record_packet(100);

    tracker.reset();

    assert!(tracker.time_since_last_packet_ms().is_none());
    assert_eq!(
        tracker.current_packet_rate_ms(),
        TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT
    );
}
