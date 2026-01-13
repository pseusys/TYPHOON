use crate::bytes::ByteBuffer;
use crate::flow::envelope::Envelope;
use crate::tailor::ENCRYPTED_TAILOR_SIZE;

#[test]
fn test_envelope_creation() {
    let payload = ByteBuffer::from(&[0x11; 100]);
    let tailor = ByteBuffer::from(&[0x22; ENCRYPTED_TAILOR_SIZE]);

    let envelope = Envelope::payload_only(payload, tailor).unwrap();

    assert_eq!(envelope.len(), 100 + ENCRYPTED_TAILOR_SIZE);
    assert_eq!(envelope.header_length, 0);
}

#[test]
fn test_envelope_with_header() {
    let header = ByteBuffer::from(&[0xFF; 16]);
    let payload = ByteBuffer::from(&[0x11; 50]);
    let tailor = ByteBuffer::from(&[0x22; ENCRYPTED_TAILOR_SIZE]);

    let envelope = Envelope::new(Some(header), payload, tailor, None).unwrap();

    assert_eq!(envelope.len(), 16 + 50 + ENCRYPTED_TAILOR_SIZE);
    assert_eq!(envelope.header_length, 16);
}

#[test]
fn test_envelope_with_body() {
    let payload = ByteBuffer::from(&[0x11; 50]);
    let tailor = ByteBuffer::from(&[0x22; ENCRYPTED_TAILOR_SIZE]);
    let body = ByteBuffer::from(&[0xAA; 32]);

    let envelope = Envelope::new(None, payload, tailor, Some(body)).unwrap();

    assert_eq!(envelope.len(), 50 + ENCRYPTED_TAILOR_SIZE + 32);
}

#[test]
fn test_extract_tailor() {
    let payload = ByteBuffer::from(&[0x11; 100]);
    let tailor = ByteBuffer::from(&[0x22; ENCRYPTED_TAILOR_SIZE]);

    let envelope = Envelope::payload_only(payload, tailor).unwrap();
    let (body, extracted_tailor) =
        Envelope::extract_tailor_from_end(envelope.into_buffer()).unwrap();

    assert_eq!(body.len(), 100);
    assert_eq!(extracted_tailor.len(), ENCRYPTED_TAILOR_SIZE);
    assert_eq!(extracted_tailor.slice()[0], 0x22);
}

#[test]
fn test_invalid_tailor_size() {
    let payload = ByteBuffer::from(&[0x11; 100]);
    let invalid_tailor = ByteBuffer::from(&[0x22; 10]); // Wrong size

    let result = Envelope::payload_only(payload, invalid_tailor);
    assert!(result.is_err());
}
