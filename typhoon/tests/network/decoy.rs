/// Decoy strategy tests.
///
/// The `FM` type parameter has been removed from all four heavy/noisy/smooth/sparse providers
/// (replaced with `Weak<dyn DecoyFlowSender>`) so they are now nameable with two type params.
/// Each test below exercises the full feed_input / feed_output path end-to-end.
use futures::channel::oneshot;
use typhoon::bytes::StaticByteBuffer;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor};
use typhoon::flow::decoy::{DecoyCommunicationMode, HeavyDecoyProvider, NoisyDecoyProvider, SimpleDecoyProvider, SmoothDecoyProvider, SparseDecoyProvider};

use super::common::{connect_with_decoy, default_settings, free_addr, setup_server};

// ── helper ────────────────────────────────────────────────────────────────────

/// Echo N messages through the server and assert round-trip correctness.
async fn run_echo_burst<DP>(n: usize, provider_name: &str)
where
    DP: DecoyCommunicationMode<StaticByteBuffer, DefaultExecutor> + Send + Sync + 'static,
{
    let settings = default_settings();
    let addr = free_addr();
    let (listener, cert) = setup_server(addr, settings.clone()).await;

    let (tx, rx) = oneshot::channel::<usize>();
    let lh = listener.clone();
    settings.executor().spawn(async move {
        let client = lh.accept().await.expect("accept");
        let mut count = 0;
        while count < n {
            let d = client.receive_bytes().await.expect("server recv");
            client.send_bytes(&d).await.expect("server echo");
            count += 1;
        }
        let _ = tx.send(count);
    });

    let socket = connect_with_decoy::<DP, _>(cert, settings, DefaultClientConnectionHandler).await;
    for i in 0..n {
        let msg = format!("{}-burst-{:03}", provider_name, i);
        socket.send_bytes(msg.as_bytes()).await.expect("send");
        let resp = socket.receive_bytes().await.expect("recv");
        assert_eq!(resp, msg.as_bytes());
    }

    assert_eq!(rx.await.expect("server task"), n);
}

// ── SimpleDecoyProvider (passthrough, original tests) ─────────────────────────

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

    let socket = connect_with_decoy::<SimpleDecoyProvider, _>(cert, settings, DefaultClientConnectionHandler).await;
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
    let socket = connect_with_decoy::<SimpleDecoyProvider, _>(cert, settings, DefaultClientConnectionHandler).await;
    let first = socket.max_data_payload();
    let second = socket.max_data_payload();
    assert_eq!(first, second, "max_data_payload must be deterministic");
    assert!(first > 0);
}

// ── HeavyDecoyProvider ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_decoy_heavy_burst() {
    run_echo_burst::<HeavyDecoyProvider<StaticByteBuffer, DefaultExecutor>>(10, "heavy").await;
}

// ── NoisyDecoyProvider ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_decoy_noisy_burst() {
    run_echo_burst::<NoisyDecoyProvider<StaticByteBuffer, DefaultExecutor>>(10, "noisy").await;
}

// ── SmoothDecoyProvider ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_decoy_smooth_burst() {
    run_echo_burst::<SmoothDecoyProvider<StaticByteBuffer, DefaultExecutor>>(10, "smooth").await;
}

// ── SparseDecoyProvider ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_decoy_sparse_burst() {
    run_echo_burst::<SparseDecoyProvider<StaticByteBuffer, DefaultExecutor>>(10, "sparse").await;
}
