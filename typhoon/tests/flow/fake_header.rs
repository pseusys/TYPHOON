use crate::flow::fake_header::{FakeHeaderGenerator, FieldType};

#[test]
fn test_random_field() {
    let mut field = FieldType::random(16);
    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];

    field.generate_into(&mut buf1);
    field.generate_into(&mut buf2);

    // Random fields should (almost certainly) produce different values
    assert_ne!(buf1, buf2);
}

#[test]
fn test_constant_field() {
    let mut field = FieldType::constant(vec![0xAB; 8]);
    let mut buf1 = [0u8; 8];
    let mut buf2 = [0u8; 8];

    field.generate_into(&mut buf1);
    field.generate_into(&mut buf2);

    assert_eq!(buf1, buf2);
    assert_eq!(buf1, [0xAB; 8]);
}

#[test]
fn test_incremental_field() {
    let mut field = FieldType::incremental(4, 0);
    let mut buf = [0u8; 4];

    field.generate_into(&mut buf);
    assert_eq!(buf, [0, 0, 0, 0]);

    field.generate_into(&mut buf);
    assert_eq!(buf, [0, 0, 0, 1]);

    field.generate_into(&mut buf);
    assert_eq!(buf, [0, 0, 0, 2]);
}

#[test]
fn test_header_generator() {
    let fields = vec![
        FieldType::constant(vec![0xFF; 2]),
        FieldType::incremental(2, 1),
    ];
    let mut generator = FakeHeaderGenerator::new(fields, 1.0);

    assert_eq!(generator.length(), 4);

    let header = generator.generate().unwrap();
    assert_eq!(header.len(), 4);
    assert_eq!(&header.slice()[0..2], &[0xFF, 0xFF]);
    assert_eq!(&header.slice()[2..4], &[0x00, 0x01]);
}

#[test]
fn test_header_probability() {
    let mut generator = FakeHeaderGenerator::new(vec![FieldType::random(4)], 0.0);

    // With 0% probability, should never include
    for _ in 0..100 {
        assert!(generator.generate().is_none());
    }
}
