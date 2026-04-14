use super::*;

// Test: make_probe produces a buffer of the correct length with the expected header fields.
#[test]
fn test_make_probe_layout() {
    let probe = make_probe(PHASE_REACHABILITY, 42, 0);
    assert_eq!(probe.len(), PROBE_HEADER_SIZE, "probe with no extra padding must be exactly PROBE_HEADER_SIZE bytes");

    let seq = u32::from_be_bytes(probe[0..4].try_into().unwrap());
    assert_eq!(seq, 42, "sequence number must be at offset 0");

    let phase = u32::from_be_bytes(probe[4..8].try_into().unwrap());
    assert_eq!(phase, PHASE_REACHABILITY, "phase must be at offset 4");
}

// Test: make_probe with extra padding produces PROBE_HEADER_SIZE + extra bytes.
#[test]
fn test_make_probe_with_padding() {
    let probe = make_probe(PHASE_THROUGHPUT, 1, 100);
    assert_eq!(probe.len(), PROBE_HEADER_SIZE + 100);
}

// Test: stamp_probe updates sequence number without changing the phase.
#[test]
fn test_stamp_probe_updates_sequence() {
    let mut probe = make_probe(PHASE_RETURN_TIME, 0, 0);
    stamp_probe(&mut probe, 99);

    let seq = u32::from_be_bytes(probe[0..4].try_into().unwrap());
    assert_eq!(seq, 99, "stamp_probe must update sequence number");

    let phase = u32::from_be_bytes(probe[4..8].try_into().unwrap());
    assert_eq!(phase, PHASE_RETURN_TIME, "stamp_probe must not modify phase field");
}

// Test: parse_send_time extracts a plausible timestamp from a freshly made probe.
#[test]
fn test_parse_send_time_roundtrip() {
    let probe = make_probe(PHASE_RETURN_TIME, 0, 0);
    let send_time = parse_send_time(&probe);
    assert!(send_time.is_some(), "parse_send_time must succeed for a valid probe");
    assert!(send_time.unwrap() > 0, "send_time must be nonzero");
}

// Test: parse_send_time returns None for a buffer that is too short.
#[test]
fn test_parse_send_time_too_short() {
    assert!(parse_send_time(&[0u8; 7]).is_none(), "must return None when buffer is shorter than 16 bytes");
}

// Test: DebugMode flag methods enable exactly the expected phases.
#[test]
fn test_debug_mode_flags() {
    assert!(DebugMode::Reachability.run_reachability());
    assert!(!DebugMode::Reachability.run_rtt());
    assert!(!DebugMode::Reachability.run_throughput());

    assert!(!DebugMode::ReturnTime.run_reachability());
    assert!(DebugMode::ReturnTime.run_rtt());
    assert!(!DebugMode::ReturnTime.run_throughput());

    assert!(!DebugMode::Throughput.run_reachability());
    assert!(!DebugMode::Throughput.run_rtt());
    assert!(DebugMode::Throughput.run_throughput());

    assert!(DebugMode::All.run_reachability());
    assert!(DebugMode::All.run_rtt());
    assert!(DebugMode::All.run_throughput());
}
