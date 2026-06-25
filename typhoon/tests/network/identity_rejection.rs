/// Identity-rejection tests: `ServerConnectionHandler::generate()` returning `None` aborts the
/// handshake (with a TERMINATION carrying `ReturnCode::IdentityRejected`) without ever producing
/// a `ClientHandle`.
use std::sync::Arc;
use std::time::Duration;

use typhoon::bytes::StaticByteBuffer;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor};
use typhoon::socket::{ClientSocketBuilder, Listener, ServerBuilder, ServerConnectionHandler, ServerFlowConfiguration};

use super::common::{default_settings, empty_flow_config, free_addr, server_key_pair};

/// Rejects every handshake: `generate()` always returns `None`.
struct RejectingConnectionHandler;

impl ServerConnectionHandler<StaticByteBuffer> for RejectingConnectionHandler {
    fn generate(&self, _initial_data: &[u8]) -> Option<StaticByteBuffer> {
        None
    }

    fn initial_data(&self, _identity: &StaticByteBuffer) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn verify_version(&self, _version_bytes: &[u8]) -> bool {
        true
    }
}

// Test: a handshake whose generate() call returns None never produces a ClientHandle — accept()
// must not resolve for it.
#[tokio::test(flavor = "multi_thread")]
async fn test_generate_none_rejects_handshake_without_accepting() {
    let settings = default_settings();
    let addr = free_addr();
    let key_pair = server_key_pair();
    let cert = key_pair.to_client_certificate(vec![addr]);

    let listener: Arc<Listener<StaticByteBuffer, DefaultExecutor, RejectingConnectionHandler>> = Arc::new(ServerBuilder::<StaticByteBuffer, DefaultExecutor, RejectingConnectionHandler>::new(key_pair, RejectingConnectionHandler).add_flow(ServerFlowConfiguration::with_address(empty_flow_config(), addr)).with_settings(settings.clone()).build_listener().await.expect("listener should build"));
    listener.start().await;

    // The client's own build() will retry against the unresponsive handshake and eventually
    // fail too, but that takes a while — discard the result, since what matters here is the
    // server side, checked below with a short timeout.
    let client_settings = settings.clone();
    settings.executor().spawn(async move {
        let _ = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(cert, DefaultClientConnectionHandler).with_settings(client_settings).build().await;
    });

    let accept_result = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
    assert!(accept_result.is_err(), "accept() must not resolve for a handshake generate() rejected");
}
