use super::{SettingType, SettingValue};

// ── SettingValue::Add ─────────────────────────────────────────────────────────

#[test]
fn test_add_signed_signed() {
    let result = SettingValue::Signed(3) + SettingValue::Signed(4);
    assert!(matches!(result, SettingValue::Signed(7)));
}

#[test]
fn test_add_unsigned_unsigned() {
    let result = SettingValue::Unsigned(10) + SettingValue::Unsigned(5);
    assert!(matches!(result, SettingValue::Unsigned(15)));
}

#[test]
fn test_add_float_float() {
    let result = SettingValue::Float(1.5) + SettingValue::Float(2.5);
    if let SettingValue::Float(v) = result {
        assert!((v - 4.0).abs() < 1e-9);
    } else {
        panic!("expected Float");
    }
}

#[test]
fn test_add_signed_unsigned_yields_float() {
    let result = SettingValue::Signed(3) + SettingValue::Unsigned(4);
    assert!(matches!(result, SettingValue::Float(_)));
}

#[test]
fn test_add_unsigned_signed_yields_float() {
    let result = SettingValue::Unsigned(4) + SettingValue::Signed(3);
    assert!(matches!(result, SettingValue::Float(_)));
}

#[test]
fn test_add_signed_float_yields_float() {
    let result = SettingValue::Signed(2) + SettingValue::Float(1.0);
    if let SettingValue::Float(v) = result {
        assert!((v - 3.0).abs() < 1e-9);
    } else {
        panic!("expected Float");
    }
}

#[test]
fn test_add_float_signed_yields_float() {
    let result = SettingValue::Float(1.0) + SettingValue::Signed(2);
    if let SettingValue::Float(v) = result {
        assert!((v - 3.0).abs() < 1e-9);
    } else {
        panic!("expected Float");
    }
}

#[test]
fn test_add_unsigned_float_yields_float() {
    let result = SettingValue::Unsigned(3) + SettingValue::Float(0.5);
    if let SettingValue::Float(v) = result {
        assert!((v - 3.5).abs() < 1e-9);
    } else {
        panic!("expected Float");
    }
}

#[test]
fn test_add_float_unsigned_yields_float() {
    let result = SettingValue::Float(0.5) + SettingValue::Unsigned(3);
    if let SettingValue::Float(v) = result {
        assert!((v - 3.5).abs() < 1e-9);
    } else {
        panic!("expected Float");
    }
}

// ── SettingType round-trips ───────────────────────────────────────────────────

#[test]
fn test_i64_roundtrip() {
    let v: i64 = -42;
    assert_eq!(i64::from_value(v.to_value()), v);
}

#[test]
fn test_u64_roundtrip() {
    let v: u64 = 1_000_000;
    assert_eq!(u64::from_value(v.to_value()), v);
}

#[test]
fn test_f64_roundtrip() {
    let v: f64 = 3.14;
    let out = f64::from_value(v.to_value());
    assert!((out - v).abs() < 1e-9);
}

#[test]
fn test_i64_try_parse_valid() {
    assert_eq!(i64::try_parse("-99"), Some(-99i64));
}

#[test]
fn test_u64_try_parse_valid() {
    assert_eq!(u64::try_parse("42"), Some(42u64));
}

#[test]
fn test_f64_try_parse_valid() {
    let v = f64::try_parse("2.71").unwrap();
    assert!((v - 2.71).abs() < 1e-9);
}

#[test]
fn test_try_parse_invalid_returns_none() {
    assert_eq!(u64::try_parse("not_a_number"), None);
    assert_eq!(i64::try_parse("also bad"), None);
    assert_eq!(f64::try_parse("??"), None);
}
