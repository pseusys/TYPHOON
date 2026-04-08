/// Decoy strategy tests.
///
/// The recursive generic constraint `DP: DecoyCommunicationMode<T, AE, ClientFlowManager<T, AE, DP>>`
/// means `HeavyDecoyProvider` et al. cannot be named with a finite type alias in test code —
/// the self-referential `FM` parameter forms an infinite type tree.  These providers are
/// exercised end-to-end by the CI example runs (`cargo run --example …`).
///
/// What we *can* test here is that `SimpleDecoyProvider` (the zero-overhead passthrough)
/// correctly forwards `feed_input` and `feed_output` for a burst of concurrent messages,
/// exercising the decoy trait dispatch path in `ClientFlowManager`.
use futures::channel::oneshot;

use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler};

use super::common::{connect_simple, default_settings, free_addr, setup_server};

// Test: many messages through SimpleDecoyProvider — exercises feed_input / feed_output paths.
#[tokio::test]
async fn test_decoy_simple_burst() {
    const N: usize = 30;
    let settings = default_settings();
    let addr = free_addr();
    let (listener, cert) = setup_server(addr, settings.clone()).await;

    let (tx, rx) = oneshot::channel::<usize>();
    let lh = listener.clone();
    settings.executor().spawn(async move {
        let client = lh.accept().await.expect("accept");
        let mut n = 0;
        while n < N {
            let d = client.receive_bytes().await.expect("server recv");
            client.send_bytes(&d).await.expect("server echo");
            n += 1;
        }
        let _ = tx.send(n);
    });

    let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
    for i in 0..N {
        let msg = format!("burst-{:03}", i);
        socket.send_bytes(msg.as_bytes()).await.expect("send");
        let resp = socket.receive_bytes().await.expect("recv");
        assert_eq!(resp, msg.as_bytes());
    }

    assert_eq!(rx.await.expect("server task"), N);
}

// Test: with SimpleDecoyProvider, max_data_payload() is stable across calls.
#[tokio::test]
async fn test_decoy_payload_size_stable() {
    let settings = default_settings();
    let addr = free_addr();
    let (_listener, cert) = setup_server(addr, settings.clone()).await;
    let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
    let first = socket.max_data_payload();
    let second = socket.max_data_payload();
    assert_eq!(first, second, "max_data_payload must be deterministic");
    assert!(first > 0);
}
