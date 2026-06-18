use crate::utils::random::jittered_chunk_size;

// Test: chunk=0 sentinel collapses to the historical single-sided behaviour —
// samples land in `[max_payload * (1 - jitter), max_payload]`.
#[test]
fn test_jittered_chunk_size_zero_sentinel_matches_max_payload() {
    let max = 1000;
    let jitter = 0.3;
    for _ in 0..256 {
        let v = jittered_chunk_size(max, 0, jitter);
        assert!(v >= ((max as f64) * (1.0 - jitter)).round() as usize);
        assert!(v <= max);
    }
}

// Test: positive chunk with jitter samples around it two-sided, clamped to [1, max_payload].
#[test]
fn test_jittered_chunk_size_positive_chunk_two_sided() {
    let max = 1500;
    let chunk = 500;
    let jitter = 0.4;
    let lo = ((chunk as f64) * (1.0 - jitter)).round() as usize;
    let hi = ((chunk as f64) * (1.0 + jitter)).round() as usize;
    for _ in 0..256 {
        let v = jittered_chunk_size(max, chunk, jitter);
        assert!(v >= lo.max(1), "value {v} below lower bound {lo}");
        assert!(v <= hi.min(max), "value {v} above upper bound {}", hi.min(max));
    }
}

// Test: chunk above max_payload is clamped to max_payload on the upper side.
#[test]
fn test_jittered_chunk_size_chunk_above_max_clamps() {
    let max = 800;
    let chunk = 1200;
    let jitter = 0.1;
    for _ in 0..64 {
        let v = jittered_chunk_size(max, chunk, jitter);
        assert!(v <= max, "value {v} above max_payload {max}");
    }
}

// Test: zero jitter and zero chunk returns max_payload deterministically.
#[test]
fn test_jittered_chunk_size_zero_jitter_zero_chunk() {
    let max = 1024;
    for _ in 0..32 {
        assert_eq!(jittered_chunk_size(max, 0, 0.0), max);
    }
}

// Test: zero jitter with positive chunk returns chunk exactly (clamped to max_payload).
#[test]
fn test_jittered_chunk_size_zero_jitter_positive_chunk() {
    assert_eq!(jittered_chunk_size(1024, 500, 0.0), 500);
    assert_eq!(jittered_chunk_size(1024, 2000, 0.0), 1024);
}

// Test: max_payload = 1 short-circuits — there is only one valid size.
#[test]
fn test_jittered_chunk_size_minimal_max_payload() {
    assert_eq!(jittered_chunk_size(1, 500, 0.5), 1);
    assert_eq!(jittered_chunk_size(1, 0, 0.5), 1);
}
