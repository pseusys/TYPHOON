/// Echo tests: basic send/receive round-trips through the full protocol stack.
use futures::channel::oneshot::channel;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler};

use super::common::{connect_simple, default_settings, free_addr, setup_server};

// Test: client sends a message, server echoes it back.
#[tokio::test]
async fn test_echo_single_message() {
    let settings = default_settings();
    let addr = free_addr();
    let (listener, cert) = setup_server(addr, settings.clone()).await;

    let (tx, rx) = channel::<Vec<u8>>();
    let lh = listener.clone();
    settings.executor().spawn(async move {
        let client = lh.accept().await.expect("accept");
        let data = client.receive_bytes().await.expect("server receive");
        client.send_bytes(&data).await.expect("server echo");
        let _ = tx.send(data);
    });

    let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
    socket.send_bytes(b"hello").await.expect("client send");
    let resp = socket.receive_bytes().await.expect("client receive");
    assert_eq!(resp, b"hello");

    let server_saw = rx.await.expect("server task");
    assert_eq!(server_saw, b"hello");
}

// Test: several sequential messages all arrive intact.
#[tokio::test]
async fn test_echo_sequential_messages() {
    const COUNT: usize = 20;
    let settings = default_settings();
    let addr = free_addr();
    let (listener, cert) = setup_server(addr, settings.clone()).await;

    let (tx, rx) = channel::<usize>();
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
        let msg = format!("msg-{:04}", i);
        socket.send_bytes(msg.as_bytes()).await.expect("send");
        let resp = socket.receive_bytes().await.expect("recv");
        assert_eq!(resp, msg.as_bytes());
    }

    assert_eq!(rx.await.expect("server task"), COUNT);
}

// Test: binary payload (all byte values 0–255 cyclically) survives a round-trip.
#[tokio::test]
async fn test_echo_binary_payload() {
    let settings = default_settings();
    let addr = free_addr();
    let (listener, cert) = setup_server(addr, settings.clone()).await;

    let payload: Vec<u8> = (0u8..=255).cycle().take(512).collect();
    let expected = payload.clone();

    let lh = listener.clone();
    settings.executor().spawn(async move {
        let client = lh.accept().await.expect("accept");
        let d = client.receive_bytes().await.expect("recv");
        client.send_bytes(&d).await.expect("echo");
    });

    let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
    socket.send_bytes(&payload).await.expect("send");
    let resp = socket.receive_bytes().await.expect("recv");
    assert_eq!(resp, expected);
}

// Test: max_data_payload() reports a non-zero value.
#[tokio::test]
async fn test_max_data_payload_nonzero() {
    let settings = default_settings();
    let addr = free_addr();
    let (_listener, cert) = setup_server(addr, settings.clone()).await;

    let socket = connect_simple(cert, settings, DefaultClientConnectionHandler).await;
    assert!(socket.max_data_payload() > 0, "max_data_payload must be positive");
}
