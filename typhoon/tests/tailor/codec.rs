use crate::bytes::ByteBuffer;
use crate::constants::tailor::TYPHOON_ID_LENGTH;
use crate::tailor::codec::{extract_encrypted_tailor, TailorCodec, ENCRYPTED_TAILOR_SIZE};
use crate::tailor::flags::PacketFlags;
use crate::tailor::structure::Tailor;

fn make_test_key() -> ByteBuffer {
    ByteBuffer::from(&[0x42u8; 32])
}

#[test]
#[cfg(feature = "fast")]
fn test_tailor_encrypt_decrypt_fast() {
    let obfs_key = make_test_key();
    let session_key = ByteBuffer::from(&[0x24u8; 32]);
    let mut codec = TailorCodec::new(&obfs_key).unwrap();

    let identity = [0xAB; TYPHOON_ID_LENGTH];
    let tailor = Tailor {
        flags: PacketFlags::DATA,
        code: 0,
        time: 64000,
        packet_number: 0x12345678_00000001,
        payload_length: 1024,
        identity,
    };

    let encrypted = codec.encrypt(&tailor, &session_key).unwrap();
    assert_eq!(encrypted.len(), ENCRYPTED_TAILOR_SIZE);

    let decrypted = codec.decrypt(encrypted, &session_key).unwrap();
    assert_eq!(decrypted.flags, tailor.flags);
    assert_eq!(decrypted.packet_number, tailor.packet_number);
    assert_eq!(decrypted.identity, tailor.identity);
}

#[test]
#[cfg(feature = "fast")]
fn test_tailor_decrypt_wrong_session_key() {
    let obfs_key = make_test_key();
    let session_key = ByteBuffer::from(&[0x24u8; 32]);
    let wrong_session_key = ByteBuffer::from(&[0x99u8; 32]);
    let mut codec = TailorCodec::new(&obfs_key).unwrap();

    let identity = [0xAB; TYPHOON_ID_LENGTH];
    let tailor = Tailor::data(identity, 512, 12345);

    let encrypted = codec.encrypt(&tailor, &session_key).unwrap();
    let result = codec.decrypt(encrypted, &wrong_session_key);

    assert!(result.is_err());
}

#[test]
fn test_extract_encrypted_tailor() {
    // Create body with append capacity for tailor
    let body = ByteBuffer::from_slice_with_capacity(&[0x11u8; 100], 0, ENCRYPTED_TAILOR_SIZE);
    let tailor_data = ByteBuffer::from(&[0x22u8; ENCRYPTED_TAILOR_SIZE]);
    let packet = body.append_buf(&tailor_data);

    let (extracted_body, extracted_tailor) = extract_encrypted_tailor(packet).unwrap();

    assert_eq!(extracted_body.len(), 100);
    assert_eq!(extracted_tailor.len(), ENCRYPTED_TAILOR_SIZE);
}

#[test]
fn test_extract_encrypted_tailor_too_small() {
    let small_packet = ByteBuffer::from(&[0x11u8; 10]);
    let result = extract_encrypted_tailor(small_packet);

    assert!(result.is_err());
}
