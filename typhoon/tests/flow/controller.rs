use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::bytes::ByteBuffer;
use crate::flow::controller::{BaseFlowManager, FlowConfig, FlowController};
use crate::tailor::ENCRYPTED_TAILOR_SIZE;

fn test_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

#[tokio::test]
async fn test_flow_config() {
    let addr = test_addr();
    let config = FlowConfig::new(addr);

    assert!(config.use_fake_header);
    assert!(config.use_fake_body);

    let minimal = FlowConfig::minimal(addr);
    assert!(!minimal.use_fake_header);
    assert!(!minimal.use_fake_body);
}

#[tokio::test]
async fn test_base_flow_manager_creation() {
    let addr = test_addr();
    let config = FlowConfig::minimal(addr);
    let manager = BaseFlowManager::new(config).await.unwrap();

    assert!(manager.local_addr().is_ok());
}

#[tokio::test]
async fn test_envelope_wrapping() {
    let addr = test_addr();
    let config = FlowConfig::minimal(addr);
    let manager = BaseFlowManager::new(config).await.unwrap();

    let payload = ByteBuffer::from(&[0x11; 100]);
    let tailor = ByteBuffer::from(&[0x22; ENCRYPTED_TAILOR_SIZE]);

    let wrapped = manager.wrap_envelope(payload, tailor).unwrap();
    assert_eq!(wrapped.len(), 100 + ENCRYPTED_TAILOR_SIZE);
}

#[tokio::test]
async fn test_envelope_unwrapping() {
    let addr = test_addr();
    let config = FlowConfig::minimal(addr);
    let manager = BaseFlowManager::new(config).await.unwrap();

    let payload = ByteBuffer::from(&[0x11; 100]);
    let tailor = ByteBuffer::from(&[0x22; ENCRYPTED_TAILOR_SIZE]);

    let wrapped = manager.wrap_envelope(payload, tailor).unwrap();
    let (body, extracted_tailor) = manager.unwrap_envelope(wrapped).unwrap();

    assert_eq!(body.len(), 100);
    assert_eq!(extracted_tailor.len(), ENCRYPTED_TAILOR_SIZE);
}
