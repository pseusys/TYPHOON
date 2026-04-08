/// Error-path tests: verify that invalid configurations are rejected at build time.
use typhoon::bytes::StaticByteBuffer;
use typhoon::defaults::{DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder};

use super::common::{default_settings, empty_flow_config, free_addr};

// Test: build() fails when the certificate contains no addresses.
#[tokio::test]
async fn test_client_build_fails_with_no_addresses() {
    let settings = default_settings();
    let key_pair = super::common::server_key_pair();
    // to_client_certificate with an empty vec → NoAddresses
    let cert = key_pair.to_client_certificate(vec![]);
    let result = ClientSocketBuilder::<
        StaticByteBuffer,
        DefaultExecutor,
        SimpleDecoyProvider,
        DefaultClientConnectionHandler,
    >::new(cert, DefaultClientConnectionHandler)
    .with_settings(settings)
    .build()
    .await;
    assert!(result.is_err(), "build should fail with no addresses in cert");
}

// Test: build() fails when with_flow_config() specifies an address not in the certificate.
#[tokio::test]
async fn test_client_build_fails_with_address_not_in_cert() {
    let settings = default_settings();
    let addr = free_addr();
    let wrong_addr = free_addr();

    let key_pair = super::common::server_key_pair();
    // Certificate only contains `addr`; we pass `wrong_addr` to with_flow_config.
    let cert = key_pair.to_client_certificate(vec![addr]);

    let result = ClientSocketBuilder::<
        StaticByteBuffer,
        DefaultExecutor,
        SimpleDecoyProvider,
        DefaultClientConnectionHandler,
    >::new(cert, DefaultClientConnectionHandler)
    .with_settings(settings)
    .with_flow_config(wrong_addr, empty_flow_config())  // wrong_addr not in cert
    .build()
    .await;

    assert!(result.is_err(), "build should fail for address not in certificate");
}

// Test: listener build() fails when no flows are added.
#[tokio::test]
async fn test_server_build_fails_with_no_flows() {
    let settings = default_settings();
    let key_pair = super::common::server_key_pair();
    let result = ListenerBuilder::<
        StaticByteBuffer,
        DefaultExecutor,
        SimpleDecoyProvider,
        DefaultServerConnectionHandler,
    >::new(key_pair, DefaultServerConnectionHandler)
    .with_settings(settings)
    .build()
    .await;
    assert!(result.is_err(), "listener build should fail with no flows");
}
