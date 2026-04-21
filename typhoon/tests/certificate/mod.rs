// Speed tip: set TYPHOON_TEST_SERVER_KEY_FAST (fast_software/fast_hardware) or
// TYPHOON_TEST_SERVER_KEY_FULL (full_software/full_hardware) to a file path before running
// these tests. ServerKeyPair::for_tests() will load the key from that file on the first call
// and save it there if absent, skipping expensive McEliece key generation on every test run.
// Example: export TYPHOON_TEST_SERVER_KEY_FAST=/tmp/typhoon_test.key && cargo test

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tempfile::NamedTempFile;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use crate::certificate::X25519_BYTES;
use crate::certificate::{CertificateError, ClientCertificate, ED25519_BYTES, EPK_BYTES, ESK_BYTES, ServerKeyPair};

impl ClientCertificate {
    pub(crate) fn epk_bytes(&self) -> &[u8] {
        self.epk.as_array()
    }
    pub(crate) fn vpk_bytes(&self) -> [u8; 32] {
        self.vpk.to_bytes()
    }
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn obfs_bytes(&self) -> &[u8] {
        self.obfs.as_ref()
    }
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn opk_bytes(&self) -> &[u8] {
        self.opk.as_bytes()
    }
}

fn two_addrs() -> Vec<SocketAddr> {
    vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 19999)), SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 20000, 0, 0))]
}

// ── ServerKeyPair ─────────────────────────────────────────────────────────────

// Test: generated key pair round-trips through save/load without data loss.
#[test]
fn test_server_key_pair_save_load_roundtrip() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    let original = ServerKeyPair::for_tests();
    original.save(&path).expect("save should succeed");
    let loaded = ServerKeyPair::load(&path).expect("load should succeed");

    assert_eq!(original.epk_bytes(), loaded.epk_bytes(), "EPK mismatch");
    assert_eq!(original.esk_bytes(), loaded.esk_bytes(), "ESK mismatch");
    assert_eq!(original.vsk_bytes(), loaded.vsk_bytes(), "VSK mismatch");
    assert_eq!(original.verifying_key_bytes(), loaded.verifying_key_bytes(), "VPK mismatch");
}

// Test: save produces exactly the expected byte-level layout (fast mode).
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[test]
fn test_server_key_pair_file_layout_fast() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    let kp = ServerKeyPair::for_tests();
    kp.save(&path).expect("save should succeed");
    let bytes = std::fs::read(&path).expect("read file");

    assert_eq!(&bytes[0..7], b"TYPHOON", "magic");
    assert_eq!(bytes[7], b'S', "type byte");
    assert_eq!(bytes[8], b'F', "mode byte");
    assert_eq!(bytes[9], 1, "version byte");
    assert_eq!(bytes.len(), 10 + EPK_BYTES + ESK_BYTES + ED25519_BYTES + ED25519_BYTES, "file size");

    assert_eq!(&bytes[10..10 + EPK_BYTES], kp.epk_bytes(), "EPK bytes");
    let esk_off = 10 + EPK_BYTES;
    assert_eq!(&bytes[esk_off..esk_off + ESK_BYTES], kp.esk_bytes(), "ESK bytes");
    let vsk_off = esk_off + ESK_BYTES;
    assert_eq!(&bytes[vsk_off..vsk_off + ED25519_BYTES], kp.vsk_bytes().as_ref(), "VSK bytes");
    let obfs_off = vsk_off + ED25519_BYTES;
    assert_eq!(&bytes[obfs_off..obfs_off + ED25519_BYTES], kp.obfs_bytes(), "OBFS bytes");
}

// Test: save produces exactly the expected byte-level layout (full mode).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
#[test]
fn test_server_key_pair_file_layout_full() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    let kp = ServerKeyPair::for_tests();
    kp.save(&path).expect("save should succeed");
    let bytes = std::fs::read(&path).expect("read file");

    assert_eq!(&bytes[0..7], b"TYPHOON", "magic");
    assert_eq!(bytes[7], b'S', "type byte");
    assert_eq!(bytes[8], b'U', "mode byte");
    assert_eq!(bytes[9], 1, "version byte");
    assert_eq!(bytes.len(), 10 + EPK_BYTES + ESK_BYTES + ED25519_BYTES + X25519_BYTES + X25519_BYTES, "file size");

    assert_eq!(&bytes[10..10 + EPK_BYTES], kp.epk_bytes(), "EPK bytes");
    let esk_off = 10 + EPK_BYTES;
    assert_eq!(&bytes[esk_off..esk_off + ESK_BYTES], kp.esk_bytes(), "ESK bytes");
    let vsk_off = esk_off + ESK_BYTES;
    assert_eq!(&bytes[vsk_off..vsk_off + ED25519_BYTES], kp.vsk_bytes().as_ref(), "VSK bytes");
    let opk_off = vsk_off + ED25519_BYTES;
    assert_eq!(&bytes[opk_off..opk_off + X25519_BYTES], kp.opk_bytes(), "OPK bytes");
    let osk_off = opk_off + X25519_BYTES;
    assert_eq!(&bytes[osk_off..osk_off + X25519_BYTES], kp.osk_bytes().as_ref(), "OSK bytes");
}

// Test: loading a file with bad magic bytes returns InvalidMagic.
#[test]
fn test_server_key_pair_bad_magic() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    ServerKeyPair::for_tests().save(&path).expect("save should succeed");
    let mut bytes = std::fs::read(&path).expect("read file");
    bytes[0] = b'X';
    std::fs::write(&path, &bytes).expect("write tampered file");

    let err = ServerKeyPair::load(&path).expect_err("should fail");
    assert!(matches!(err, CertificateError::InvalidMagic), "expected InvalidMagic, got {:?}", err);
}

// Test: loading a client certificate file as a server key pair returns InvalidType.
#[test]
fn test_server_key_pair_wrong_type() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    ServerKeyPair::for_tests().to_client_certificate(vec![]).save(&path).expect("save should succeed");

    let err = ServerKeyPair::load(&path).expect_err("should fail");
    assert!(matches!(err, CertificateError::InvalidType { .. }), "expected InvalidType, got {:?}", err);
}

// Test: loading a file with an unsupported version byte returns UnsupportedVersion.
#[test]
fn test_server_key_pair_unsupported_version() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    ServerKeyPair::for_tests().save(&path).expect("save should succeed");
    let mut bytes = std::fs::read(&path).expect("read file");
    bytes[9] = 99;
    std::fs::write(&path, &bytes).expect("write tampered file");

    let err = ServerKeyPair::load(&path).expect_err("should fail");
    assert!(matches!(err, CertificateError::UnsupportedVersion(99)), "expected UnsupportedVersion(99), got {:?}", err);
}

// ── ClientCertificate ─────────────────────────────────────────────────────────

// Test: client certificate round-trips through save/load, preserving keys and addresses.
#[test]
fn test_client_certificate_save_load_roundtrip() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    let addrs = two_addrs();
    let cert = ServerKeyPair::for_tests().to_client_certificate(addrs.clone());
    cert.save(&path).expect("save should succeed");
    let loaded = ClientCertificate::load(&path).expect("load should succeed");

    assert_eq!(cert.epk_bytes(), loaded.epk_bytes(), "EPK mismatch");
    assert_eq!(cert.vpk_bytes(), loaded.vpk_bytes(), "VPK mismatch");
    assert_eq!(loaded.addresses(), addrs.as_slice(), "addresses mismatch");
}

// Test: save produces exactly the expected byte-level layout (fast mode).
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[test]
fn test_client_certificate_file_layout_fast() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    let addrs = two_addrs();
    let cert = ServerKeyPair::for_tests().to_client_certificate(addrs);
    cert.save(&path).expect("save should succeed");
    let bytes = std::fs::read(&path).expect("read file");

    assert_eq!(&bytes[0..7], b"TYPHOON", "magic");
    assert_eq!(bytes[7], b'C', "type byte");
    assert_eq!(bytes[8], b'F', "mode byte");
    assert_eq!(bytes[9], 1, "version byte");

    assert_eq!(&bytes[10..10 + EPK_BYTES], cert.epk_bytes(), "EPK bytes");
    let vpk_off = 10 + EPK_BYTES;
    assert_eq!(&bytes[vpk_off..vpk_off + ED25519_BYTES], cert.vpk_bytes().as_ref(), "VPK bytes");
    let obfs_off = vpk_off + ED25519_BYTES;
    assert_eq!(&bytes[obfs_off..obfs_off + ED25519_BYTES], cert.obfs_bytes(), "OBFS bytes");

    // ADDR_COUNT = 2 as big-endian u16.
    let addr_count_off = obfs_off + ED25519_BYTES;
    assert_eq!(u16::from_be_bytes([bytes[addr_count_off], bytes[addr_count_off + 1]]), 2, "addr count");

    // IPv4 entry: family=4, 4 octets, 2-byte port.
    let a0 = addr_count_off + 2;
    assert_eq!(bytes[a0], 4, "IPv4 family byte");
    assert_eq!(&bytes[a0 + 1..a0 + 5], &[127, 0, 0, 1], "IPv4 octets");
    assert_eq!(u16::from_be_bytes([bytes[a0 + 5], bytes[a0 + 6]]), 19999, "IPv4 port");

    // IPv6 entry: family=6, 16 octets, 2-byte port.
    let a1 = a0 + 7;
    assert_eq!(bytes[a1], 6, "IPv6 family byte");
    assert_eq!(&bytes[a1 + 1..a1 + 17], Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).octets().as_ref(), "IPv6 octets");
    assert_eq!(u16::from_be_bytes([bytes[a1 + 17], bytes[a1 + 18]]), 20000, "IPv6 port");
    assert_eq!(bytes.len(), a1 + 19, "total file size");
}

// Test: save produces exactly the expected byte-level layout (full mode).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
#[test]
fn test_client_certificate_file_layout_full() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    let cert = ServerKeyPair::for_tests().to_client_certificate(two_addrs());
    cert.save(&path).expect("save should succeed");
    let bytes = std::fs::read(&path).expect("read file");

    assert_eq!(&bytes[0..7], b"TYPHOON", "magic");
    assert_eq!(bytes[7], b'C', "type byte");
    assert_eq!(bytes[8], b'U', "mode byte");
    assert_eq!(bytes[9], 1, "version byte");

    assert_eq!(&bytes[10..10 + EPK_BYTES], cert.epk_bytes(), "EPK bytes");
    let vpk_off = 10 + EPK_BYTES;
    assert_eq!(&bytes[vpk_off..vpk_off + ED25519_BYTES], cert.vpk_bytes().as_ref(), "VPK bytes");
    let opk_off = vpk_off + ED25519_BYTES;
    assert_eq!(&bytes[opk_off..opk_off + X25519_BYTES], cert.opk_bytes(), "OPK bytes");

    let addr_count_off = opk_off + X25519_BYTES;
    assert_eq!(u16::from_be_bytes([bytes[addr_count_off], bytes[addr_count_off + 1]]), 2, "addr count");
}

// Test: certificate with no addresses saves and loads correctly.
#[test]
fn test_client_certificate_empty_addresses() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    let cert = ServerKeyPair::for_tests().to_client_certificate(vec![]);
    cert.save(&path).expect("save should succeed");
    let loaded = ClientCertificate::load(&path).expect("load should succeed");
    assert!(loaded.addresses().is_empty(), "addresses should be empty");
}

// Test: loading a server key pair file as a client certificate returns InvalidType.
#[test]
fn test_client_certificate_wrong_type() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    ServerKeyPair::for_tests().save(&path).expect("save should succeed");

    let err = ClientCertificate::load(&path).expect_err("should fail");
    assert!(matches!(err, CertificateError::InvalidType { .. }), "expected InvalidType, got {:?}", err);
}

// Test: loading a file with an unsupported version byte returns UnsupportedVersion.
#[test]
fn test_client_certificate_unsupported_version() {
    let path = NamedTempFile::new().expect("tempfile").into_temp_path();
    ServerKeyPair::for_tests().to_client_certificate(vec![]).save(&path).expect("save should succeed");
    let mut bytes = std::fs::read(&path).expect("read file");
    bytes[9] = 42;
    std::fs::write(&path, &bytes).expect("write tampered file");

    let err = ClientCertificate::load(&path).expect_err("should fail");
    assert!(matches!(err, CertificateError::UnsupportedVersion(42)), "expected UnsupportedVersion(42), got {:?}", err);
}

// Test: two certificates derived from the same key pair contain identical public material.
#[test]
fn test_to_client_certificate_consistency() {
    let kp = ServerKeyPair::for_tests();
    let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let cert1 = kp.to_client_certificate(vec![addr]);
    let cert2 = kp.to_client_certificate(vec![addr]);

    assert_eq!(cert1.epk_bytes(), cert2.epk_bytes(), "EPK must be the same");
    assert_eq!(cert1.vpk_bytes(), cert2.vpk_bytes(), "VPK must be the same");
    assert_eq!(cert1.addresses(), cert2.addresses(), "addresses must be the same");
}
