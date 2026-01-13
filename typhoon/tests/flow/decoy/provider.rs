use crate::flow::decoy::provider::{BaseDecoyProvider, DecoyMode, DecoyProvider};

#[test]
fn test_decoy_mode_default() {
    assert_eq!(DecoyMode::default(), DecoyMode::None);
}

#[test]
fn test_provider_mode() {
    let provider = BaseDecoyProvider::new(DecoyMode::Heavy);
    assert_eq!(provider.mode(), DecoyMode::Heavy);

    provider.set_mode(DecoyMode::Noisy);
    assert_eq!(provider.mode(), DecoyMode::Noisy);
}

#[test]
fn test_maybe_generate_decoy_disabled() {
    let provider = BaseDecoyProvider::new(DecoyMode::None);
    assert!(provider.maybe_generate_decoy().is_none());
}

#[test]
fn test_next_delay() {
    let provider = BaseDecoyProvider::new(DecoyMode::None);
    assert!(provider.next_decoy_delay_ms().is_none());

    provider.set_mode(DecoyMode::Heavy);
    assert!(provider.next_decoy_delay_ms().is_some());
}

#[test]
fn test_generate_decoy() {
    let provider = BaseDecoyProvider::new(DecoyMode::Heavy);
    let decoy = provider.generate_decoy();
    assert!(decoy.len() >= crate::constants::decoy::TYPHOON_DECOY_LENGTH_MIN);
}

#[test]
fn test_on_packet_sent() {
    let provider = BaseDecoyProvider::new(DecoyMode::Smooth);
    provider.on_packet_sent(100);
    provider.on_packet_sent(200);

    // Rate tracker should have recorded packets
    assert!(provider.rate_tracker().time_since_last_packet_ms().is_some());
}
