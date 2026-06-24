/// Handshake replay tests: a captured handshake packet must not be able to kill an active
/// connection by being replayed against the server later.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use tokio::net::UdpSocket;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor};
use typhoon::settings::Settings;
use typhoon::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use typhoon::socket::{Listener, ServerBuilder, ServerConnectionHandler, ServerFlowConfiguration};

use super::common::{connect_simple, default_settings, empty_flow_config, free_addr, server_key_pair};

/// Identity generator that always derives the same fixed identity, regardless of initial data —
/// the "initial data is random data encrypted by the server" deployment mode from PROTOCOL.md
/// collapses to this when there's only ever one client, letting a replayed handshake collide
/// with the real session's identity so the replay gate's existing-session branch is exercised.
struct FixedIdentityHandler;

impl ServerConnectionHandler<StaticByteBuffer> for FixedIdentityHandler {
    fn generate(&self, _initial_data: &[u8]) -> Option<StaticByteBuffer> {
        Some(StaticByteBuffer::from_slice(&[0x42u8; DEFAULT_TYPHOON_ID_LENGTH]))
    }

    fn initial_data(&self, _identity: &StaticByteBuffer) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn verify_version(&self, _version_bytes: &[u8]) -> bool {
        true
    }
}

/// Build a `ServerKeyPair`-backed listener using `FixedIdentityHandler` instead of the default
/// random identity generator.
async fn listener_with_fixed_identity(addr: SocketAddr, settings: Arc<Settings<DefaultExecutor>>, key_pair: ServerKeyPair) -> Arc<Listener<StaticByteBuffer, DefaultExecutor, FixedIdentityHandler>> {
    let listener = ServerBuilder::<StaticByteBuffer, DefaultExecutor, FixedIdentityHandler>::new(key_pair, FixedIdentityHandler).add_flow(ServerFlowConfiguration::with_address(empty_flow_config(), addr)).with_settings(settings).build_listener().await.expect("listener should build");
    let listener = Arc::new(listener);
    listener.start().await;
    listener
}

/// Transparent UDP relay between one client and the server. Forwards every datagram in both
/// directions so the connection behaves normally, while recording a copy of the first
/// client-to-server datagram (the handshake) for later replay.
async fn run_relay(relay_sock: UdpSocket, server_addr: SocketAddr, captured: Arc<StdMutex<Option<Vec<u8>>>>) {
    let mut buf = vec![0u8; 4096];
    let mut client_addr = None;
    loop {
        let Ok((n, from)) = relay_sock.recv_from(&mut buf).await else {
            return;
        };
        let data = &buf[..n];
        if from == server_addr {
            if let Some(addr) = client_addr {
                let _ = relay_sock.send_to(data, addr).await;
            }
        } else {
            if client_addr.is_none() {
                client_addr = Some(from);
            }
            {
                let mut guard = captured.lock().expect("capture lock");
                if guard.is_none() {
                    *guard = Some(data.to_vec());
                }
            }
            let _ = relay_sock.send_to(data, server_addr).await;
        }
    }
}

// Test: replaying a captured handshake packet against the server, while the session it
// established is still the live one, is rejected and does not disturb the active connection.
#[tokio::test(flavor = "multi_thread")]
async fn test_replayed_handshake_does_not_kill_active_connection() {
    let settings = default_settings();
    let server_addr = free_addr();
    let relay_addr = free_addr();

    let key_pair = server_key_pair();
    let cert_via_relay = key_pair.to_client_certificate(vec![relay_addr]);
    let listener = listener_with_fixed_identity(server_addr, settings.clone(), key_pair).await;

    let captured: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
    let relay_sock = UdpSocket::bind(relay_addr).await.expect("relay bind");
    settings.executor().spawn(run_relay(relay_sock, server_addr, Arc::clone(&captured)));

    let lh = listener.clone();
    settings.executor().spawn(async move {
        let client = lh.accept().await.expect("accept");
        while let Ok(data) = client.receive_bytes().await {
            if client.send_bytes(&data).await.is_err() {
                break;
            }
        }
    });

    let socket = connect_simple(cert_via_relay, settings.clone(), DefaultClientConnectionHandler).await;

    // Prove the connection is alive before the replay attempt.
    socket.send_bytes(b"before-replay").await.expect("send before replay");
    let resp = socket.receive_bytes().await.expect("recv before replay");
    assert_eq!(resp, b"before-replay");

    let handshake_bytes = captured.lock().expect("capture lock").clone().expect("handshake must have been captured by the relay");

    // Replay the captured handshake directly at the server, bypassing the relay entirely —
    // simulating an on-path observer resending a previously captured packet.
    let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.expect("attacker bind");
    attacker_sock.send_to(&handshake_bytes, server_addr).await.expect("replay send");

    // Give the server a moment to process (and, if the bug were present, to tear down/terminate
    // the live session).
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The active connection must still be fully functional after the replay attempt.
    socket.send_bytes(b"after-replay").await.expect("send after replay");
    let resp = socket.receive_bytes().await.expect("recv after replay — replay must not have killed the session");
    assert_eq!(resp, b"after-replay");
}
