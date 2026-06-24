/// Mimic-probe example: a custom `ActiveProbeHandler` that mimics a Redis-style error reply for
/// every packet the server can't identify as TYPHOON traffic, instead of the default silent drop
/// (`NoopProbeHandler`).
///
/// Legitimate client traffic round-trips normally; a raw, undersized UDP datagram sent directly
/// at the server (bypassing TYPHOON entirely) gets the mimicked reply instead of silence.
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use env_logger::init;
use futures::channel::oneshot::channel;
#[cfg(not(feature = "tokio"))]
use futures::executor::block_on;
use log::warn;
#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;
use typhoon::bytes::{ByteBufferMut, DynamicByteBuffer};
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{ActiveProbeHandler, AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler, ProbeFlowSender};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::{Settings, SettingsBuilder};
use typhoon::socket::{ClientSocketBuilder, ServerBuilder, ServerFlowConfiguration};

const SERVER_ADDR: &str = "127.0.0.1:19989";
const MSG_COUNT: usize = 10;
const PAYLOAD_SIZE: usize = 256;
/// Fixed reply mimicking a Redis protocol error — any plausible non-TYPHOON banner works here;
/// PROTOCOL.md deliberately does not prescribe a specific protocol to impersonate.
const MIMIC_RESPONSE: &[u8] = b"-ERR unknown command\r\n";

type Ident = typhoon::bytes::StaticByteBuffer;
type Exec = DefaultExecutor;

// ── Custom active probe handler ────────────────────────────────────────────────

/// Replies to every unidentified packet with `MIMIC_RESPONSE` instead of staying silent.
/// `manager`/`settings` arrive via `start()`, after construction, per `ActiveProbeHandler`.
struct MimicProbeHandler<AE: AsyncExecutor> {
    manager: Option<Weak<dyn ProbeFlowSender>>,
    settings: Option<Arc<Settings<AE>>>,
}

impl<AE: AsyncExecutor> Default for MimicProbeHandler<AE> {
    fn default() -> Self {
        Self {
            manager: None,
            settings: None,
        }
    }
}

#[async_trait]
impl<AE: AsyncExecutor + 'static> ActiveProbeHandler<AE> for MimicProbeHandler<AE> {
    async fn start(&mut self, manager: Weak<dyn ProbeFlowSender>, settings: Arc<Settings<AE>>) {
        self.manager = Some(manager);
        self.settings = Some(settings);
    }

    async fn process(&mut self, _packet: DynamicByteBuffer, source: Option<SocketAddr>) {
        let (Some(source), Some(manager), Some(settings)) = (source, self.manager.as_ref().and_then(Weak::upgrade), self.settings.as_ref()) else {
            return;
        };
        let buf = settings.pool().allocate(Some(MIMIC_RESPONSE.len()));
        buf.slice_mut().copy_from_slice(MIMIC_RESPONSE);
        if let Err(err) = manager.send_raw(buf, source).await {
            warn!("MimicProbeHandler: send failed: {err:?}");
        }
    }
}

// ── Runtime boilerplate ───────────────────────────────────────────────────────

#[cfg(feature = "tokio")]
fn main() {
    Runtime::new().expect("failed to create tokio runtime").block_on(run());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    block_on(run());
}

async fn run() {
    init();

    let settings = Arc::new(SettingsBuilder::<Exec>::new().build().expect("default settings should be valid"));
    let server_addr = SERVER_ADDR.parse().expect("valid address");

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![server_addr]);

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));
    let server_flow = ServerFlowConfiguration::<Ident, Exec>::with_address(flow_config, server_addr).with_probe::<MimicProbeHandler<Exec>>();

    let listener: Arc<_> = Arc::new(ServerBuilder::<Ident, Exec, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(server_flow).with_settings(settings.clone()).build_listener().await.expect("listener should build"));
    listener.start().await;
    println!("Server: listening on {server_addr} with a custom (Redis-mimicking) active probe handler");

    let (done_tx, done_rx) = channel::<usize>();
    let listener_handle = listener.clone();
    settings.executor().spawn(async move {
        let client = listener_handle.accept().await.expect("accept should succeed");
        let mut count = 0;
        while count < MSG_COUNT {
            let data = client.receive_bytes().await.expect("receive should succeed");
            client.send_bytes(&data).await.expect("echo send should succeed");
            count += 1;
        }
        let _ = done_tx.send(count);
    });

    // --- Legitimate client traffic: unaffected by the probe handler ---
    let socket = ClientSocketBuilder::<Ident, Exec, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_settings(settings.clone()).build().await.expect("client socket should build");
    let payload = vec![0xABu8; PAYLOAD_SIZE];
    for _ in 0..MSG_COUNT {
        socket.send_bytes(&payload).await.expect("send should succeed");
        socket.receive_bytes().await.expect("receive echo should succeed");
    }
    let echoed = done_rx.await.expect("server task should complete");
    assert_eq!(echoed, MSG_COUNT, "server echoed wrong count");
    println!("Client: {MSG_COUNT} legitimate round trips completed normally");

    // --- An undersized, non-TYPHOON datagram sent directly at the server ---
    // Far shorter than any valid encrypted tailer, so the flow manager forwards it to the probe
    // handler regardless of any other protocol detail (see PROTOCOL.md "Active probing protection").
    let probe_socket = UdpSocket::bind("127.0.0.1:0").expect("probe socket bind");
    probe_socket.set_read_timeout(Some(Duration::from_secs(2))).expect("set read timeout");
    probe_socket.send_to(b"not a typhoon packet", server_addr).expect("probe send");
    let mut reply = [0u8; 64];
    let (n, _) = probe_socket.recv_from(&mut reply).expect("expected a mimicked reply, got none");
    assert_eq!(&reply[..n], MIMIC_RESPONSE, "probe handler should mimic the configured response");

    println!("Success! Legitimate traffic round-tripped normally, and the unidentified packet got a mimicked Redis error instead of silence.");
}
