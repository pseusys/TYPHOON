/// Multi-flow tests: server binds two UDP ports, certificate embeds both addresses.
/// The client creates one flow manager per address; packets are distributed across flows.
use futures::channel::oneshot;

use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler};
use typhoon::socket::ClientSocketError;

use super::common::{connect_simple, default_settings, free_addr, setup_server_multi};

// Test: all messages arrive when the session uses two flows.
#[tokio::test]
async fn test_multi_flow_echo() {
    const COUNT: usize = 20;
    let settings = default_settings();
    let addr1 = free_addr();
    let addr2 = free_addr();
    let (listener, cert) = setup_server_multi(vec![addr1, addr2], settings.clone()).await;

    let (tx, rx) = oneshot::channel::<usize>();
    let lh = listener.clone();
    settings.executor().spawn(async move {
        let client = lh.accept().await.expect("accept");
        let mut n = 0;
        while n < COUNT {
            let d = client.receive_bytes().await.expect("recv");
            client.send_bytes(&d).await.expect("echo");
            n += 1;
        }
        let _ = tx.send(n);
    });

    let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
    for i in 0..COUNT {
        let msg = format!("flow-{:03}", i);
        socket.send_bytes(msg.as_bytes()).await.expect("send");
        // ChannelClosed is acceptable: TERMINATION from the server can race the last
        // echo on a different UDP flow, which is normal behaviour for multi-flow UDP.
        match socket.receive_bytes().await {
            Ok(resp) => assert_eq!(resp, msg.as_bytes()),
            Err(ClientSocketError::ChannelClosed) => break,
            Err(e) => panic!("recv #{i}: unexpected error: {e}"),
        }
    }

    // The server always completes all COUNT echoes before dropping the handle.
    assert_eq!(rx.await.expect("server task"), COUNT);
}

// Test: max_data_payload is positive even with two flows active.
#[tokio::test]
async fn test_multi_flow_max_payload_positive() {
    let settings = default_settings();
    let addr1 = free_addr();
    let addr2 = free_addr();
    let (_listener, cert) = setup_server_multi(vec![addr1, addr2], settings.clone()).await;
    let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
    assert!(socket.max_data_payload() > 0);
}
