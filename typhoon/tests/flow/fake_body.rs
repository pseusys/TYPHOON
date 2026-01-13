use crate::flow::fake_body::{FakeBodyGenerator, FakeBodyMode};

#[test]
fn test_empty_mode() {
    let generator = FakeBodyGenerator::new(FakeBodyMode::Empty);
    assert!(generator.generate().is_none());
}

#[test]
fn test_random_mode() {
    let generator = FakeBodyGenerator::new(FakeBodyMode::random(10, 20));

    for _ in 0..10 {
        let body = generator.generate().unwrap();
        assert!(body.len() >= 10);
        assert!(body.len() <= 20);
    }
}

#[test]
fn test_constant_mode() {
    let generator = FakeBodyGenerator::new(FakeBodyMode::constant(vec![0xAB; 16]));

    let body = generator.generate().unwrap();
    assert_eq!(body.len(), 16);
    assert_eq!(body.slice(), &[0xAB; 16]);
}

#[test]
fn test_generate_into() {
    let generator = FakeBodyGenerator::new(FakeBodyMode::constant(vec![0xFF; 8]));
    let mut buf = [0u8; 8];

    let written = generator.generate_into(&mut buf);
    assert_eq!(written, 8);
    assert_eq!(buf, [0xFF; 8]);
}

#[test]
fn test_default() {
    let generator = FakeBodyGenerator::default();
    // Should be random mode by default
    matches!(generator.mode(), FakeBodyMode::Random { .. });
}
