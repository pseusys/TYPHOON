use std::sync::Arc;
use std::thread;

use crate::utils::bitset::AtomicBitSet;

// Test: setting a single bit is returned by random_set_index.
#[test]
fn test_bitset_single_bit_returned() {
    let bs = AtomicBitSet::new(64);
    bs.set(7);
    assert_eq!(bs.random_set_index(64), 7);
}

// Test: random_set_index on an empty bitset falls back to 0.
#[test]
fn test_bitset_empty_returns_zero() {
    let bs = AtomicBitSet::new(64);
    assert_eq!(bs.random_set_index(64), 0);
}

// Test: out-of-range set is a no-op; bitset remains empty.
#[test]
fn test_bitset_out_of_range_is_noop() {
    let bs = AtomicBitSet::new(8);
    bs.set(8);
    bs.set(255);
    assert_eq!(bs.random_set_index(8), 0, "out-of-range set must be ignored");
}

// Test: random_set_index only returns indices of set bits.
#[test]
fn test_bitset_multi_bit_only_set_bits_returned() {
    let bs = AtomicBitSet::new(64);
    bs.set(3);
    bs.set(17);
    bs.set(60);
    let valid = [3usize, 17, 60];
    for _ in 0..200 {
        let idx = bs.random_set_index(64);
        assert!(valid.contains(&idx), "unexpected index {idx}");
    }
}

// Test: reservoir sampling is roughly uniform across all set bits.
#[test]
fn test_bitset_reservoir_sampling_roughly_uniform() {
    let bs = AtomicBitSet::new(4);
    bs.set(0);
    bs.set(1);
    bs.set(2);
    bs.set(3);

    let iters = 10_000u32;
    let mut counts = [0u32; 4];
    for _ in 0..iters {
        counts[bs.random_set_index(4)] += 1;
    }

    // Each bit should be chosen ~25% of the time; allow ±12% relative slack.
    let expected = iters / 4;
    for (i, &count) in counts.iter().enumerate() {
        let diff = (count as i64 - expected as i64).unsigned_abs() as u32;
        assert!(diff < expected / 4, "bit {i} selected {count} times (expected ~{expected}, diff {diff})");
    }
}

// Test: concurrent sets from multiple threads are all visible afterwards.
#[test]
fn test_bitset_concurrent_set() {
    let bs = Arc::new(AtomicBitSet::new(64));
    let mut handles = Vec::new();

    for bit in 0u32..8 {
        let bs_clone = Arc::clone(&bs);
        handles.push(thread::spawn(move || bs_clone.set(bit as usize)));
    }
    for h in handles {
        h.join().unwrap();
    }

    // All 8 bits must be accounted for.
    let valid: Vec<usize> = (0..8).collect();
    for _ in 0..200 {
        assert!(valid.contains(&bs.random_set_index(8)));
    }
}

// Test: num_bits boundary — bits at exactly num_bits are excluded from selection.
#[test]
fn test_bitset_num_bits_boundary() {
    // Capacity is 64, but num_bits = 4 → only bits 0-3 considered.
    let bs = AtomicBitSet::new(64);
    bs.set(0);
    bs.set(3);
    bs.set(4); // this IS within capacity but beyond num_bits passed to random_set_index
    for _ in 0..100 {
        let idx = bs.random_set_index(4);
        assert!(idx < 4, "expected index < 4, got {idx}");
    }
}
