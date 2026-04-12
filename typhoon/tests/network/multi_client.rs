/// Multi-client tests: several clients connect concurrently to one server.
/// Verifies session isolation: each client's messages are echoed only to that client.
use std::sync::Arc;

use futures::future::join_all;
use futures::channel::oneshot::channel;
use typhoon::bytes::StaticByteBuffer;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::socket::{ListenerBuilder, ServerFlowConfiguration};

use super::common::{connect_simple, default_settings, empty_flow_config, free_addr, server_key_pair};

const CLIENTS: usize = 3;
const MSGS: usize = 5;

// Test: N clients connect and get their own echo sessions from a single sequential accept loop.
#[tokio::test]
async fn test_multi_client_isolated_sessions() {
    let settings = default_settings();
    let addr = free_addr();
    let key_pair = server_key_pair();

    // Build certificates before consuming key_pair into the listener.
    let certs: Vec<_> = (0..CLIENTS).map(|_| key_pair.to_client_certificate(vec![addr])).collect();

    let listener = Arc::new(ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(ServerFlowConfiguration::with_address(empty_flow_config(), addr)).with_settings(settings.clone()).build().await.expect("listener"));
    listener.start().await;

    // A single accept loop to avoid concurrent accept() calls fighting over the WatchReceiver.
    let (total_tx, total_rx) = channel::<usize>();
    let lh = listener.clone();
    settings.executor().spawn(async move {
        let mut total = 0;
        for _ in 0..CLIENTS {
            let client = lh.accept().await.expect("accept");
            // Spawn a per-client echo task.
            let (done_tx, _done_rx) = channel::<usize>();
            DefaultExecutor::new().spawn(async move {
                let mut n = 0;
                while n < MSGS {
                    let d = client.receive_bytes().await.expect("recv");
                    client.send_bytes(&d).await.expect("echo");
                    n += 1;
                }
                let _ = done_tx.send(n);
            });
            total += 1;
        }
        let _ = total_tx.send(total);
    });

    // Connect all clients concurrently and exchange messages.
    let client_futs: Vec<_> = certs
        .into_iter()
        .enumerate()
        .map(|(id, cert)| {
            let settings = settings.clone();
            async move {
                let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
                for i in 0..MSGS {
                    let msg = format!("c{}-{}", id, i);
                    socket.send_bytes(msg.as_bytes()).await.expect("send");
                    let resp = socket.receive_bytes().await.expect("recv");
                    assert_eq!(resp, msg.as_bytes(), "payload mismatch c{} msg{}", id, i);
                }
                MSGS
            }
        })
        .collect();

    let counts = join_all(client_futs).await;
    for (id, &count) in counts.iter().enumerate() {
        assert_eq!(count, MSGS, "client {} wrong count", id);
    }

    let accepted = total_rx.await.expect("accept loop");
    assert_eq!(accepted, CLIENTS, "wrong number of clients accepted");
}
