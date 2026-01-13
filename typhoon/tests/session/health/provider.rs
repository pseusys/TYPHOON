use crate::session::health::decay::DecayState;
use crate::session::health::HealthCheckProvider;

#[test]
fn test_new_provider() {
    let provider = HealthCheckProvider::new();
    assert!(!provider.rtt_tracker().is_initialized());
    assert!(provider.is_active());
}

#[test]
fn test_handshake_complete() {
    let provider = HealthCheckProvider::new();
    provider.handshake_complete();
    assert_eq!(provider.decay_cycle().state(), DecayState::Idle);
}

#[test]
fn test_take_shadowride_receiver() {
    let mut provider = HealthCheckProvider::new();
    assert!(provider.take_shadowride_receiver().is_some());
    assert!(provider.take_shadowride_receiver().is_none());
}

#[test]
fn test_process_received() {
    let provider = HealthCheckProvider::new();
    provider.handshake_complete();

    // Prepare to send
    provider.decay_cycle().prepare_send(12345);

    // Process response
    let result = provider.process_received(12345, 100000);
    assert!(result);
    assert_eq!(provider.retry_count(), 0);
}

#[test]
fn test_terminate() {
    let provider = HealthCheckProvider::new();
    provider.terminate();
    assert!(!provider.is_active());
}
