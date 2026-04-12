/// Shared helpers for network integration tests.
use std::net::SocketAddr;
use std::sync::Arc;

use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::{ServerKeyPair, ClientCertificate};
use typhoon::defaults::{DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::{DecoyCommunicationMode, SimpleDecoyProvider};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::{Settings, SettingsBuilder};
use typhoon::socket::{ClientConnectionHandler, ClientSocket, ClientSocketBuilder, Listener, ListenerBuilder, ServerFlowConfiguration};

/// Allocate a loopback address on an OS-assigned port.
/// Bind a UDP socket briefly to learn the port, then release it so the
/// listener can bind it. (Races are acceptable in tests; ephemeral port
/// re-use failures will just make the test fail with a bind error.)
pub fn free_addr() -> SocketAddr {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("127.0.0.1:0").expect("OS should assign a free port");
    sock.local_addr().unwrap()
}

/// Build shared default settings.
pub fn default_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("default settings should be valid"))
}

/// Build a minimal flow config with no padding.
pub fn empty_flow_config() -> FlowConfig {
    FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]))
}

/// Load a server key pair from the env-var-pointed file when available,
/// otherwise generate a fresh one (and save it for subsequent runs).
///
/// Integration tests cannot access `#[cfg(test)]` items in the library,
/// so the load-or-generate logic is inlined here.
pub fn server_key_pair() -> ServerKeyPair {
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    let env_var = "TYPHOON_TEST_SERVER_KEY_FAST";
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    let env_var = "TYPHOON_TEST_SERVER_KEY_FULL";

    if let Ok(path) = std::env::var(env_var) {
        let p = std::path::Path::new(&path);
        if p.exists() {
            if let Ok(kp) = ServerKeyPair::load(p) {
                return kp;
            }
        }
        let kp = ServerKeyPair::generate();
        let _ = kp.save(p);
        kp
    } else {
        ServerKeyPair::generate()
    }
}

/// Build a listener with a caller-supplied key pair (so we can also derive a certificate).
pub async fn listener_with_key(addrs: Vec<SocketAddr>, settings: Arc<Settings<DefaultExecutor>>, key_pair: ServerKeyPair) -> Arc<Listener<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>> {
    let mut builder = ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler);

    for addr in addrs {
        builder = builder.add_flow(ServerFlowConfiguration::with_address(empty_flow_config(), addr));
    }

    let listener = Arc::new(builder.with_settings(settings).build().await.expect("listener should build"));
    listener.start().await;
    listener
}

async fn simple_listener_with_key(addr: SocketAddr, settings: Arc<Settings<DefaultExecutor>>, key_pair: ServerKeyPair) -> Arc<Listener<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>> {
    listener_with_key(vec![addr], settings, key_pair).await
}

/// Build a `ServerKeyPair`, start a listener on `addr`, and return (listener, certificate).
pub async fn setup_server(addr: SocketAddr, settings: Arc<Settings<DefaultExecutor>>) -> (Arc<Listener<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>>, ClientCertificate) {
    let key_pair = server_key_pair();
    let certificate = key_pair.to_client_certificate(vec![addr]);
    let listener = simple_listener_with_key(addr, settings, key_pair).await;
    (listener, certificate)
}

/// Build a `ServerKeyPair`, start a listener on all `addrs`, and return (listener, certificate).
pub async fn setup_server_multi(addrs: Vec<SocketAddr>, settings: Arc<Settings<DefaultExecutor>>) -> (Arc<Listener<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>>, ClientCertificate) {
    let key_pair = server_key_pair();
    let certificate = key_pair.to_client_certificate(addrs.clone());
    let listener = listener_with_key(addrs, settings, key_pair).await;
    (listener, certificate)
}

/// Build a `ClientSocket<DP>` using any `DecoyCommunicationMode` provider.
pub async fn connect_with_decoy<DP, CC>(certificate: ClientCertificate, settings: Arc<Settings<DefaultExecutor>>, handler: CC) -> ClientSocket<StaticByteBuffer, DefaultExecutor, DP, CC>
where
    DP: DecoyCommunicationMode<StaticByteBuffer, DefaultExecutor> + Send + Sync + 'static,
    CC: ClientConnectionHandler + 'static,
{
    ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DP, CC>::new(certificate, handler).with_settings(settings).build().await.expect("client socket should build")
}

/// Build a `ClientSocket<SimpleDecoyProvider>` using the given certificate and settings.
pub async fn connect_simple<CC: ClientConnectionHandler + 'static>(certificate: ClientCertificate, settings: Arc<Settings<DefaultExecutor>>, handler: CC) -> ClientSocket<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, CC> {
    ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, CC>::new(certificate, handler).with_settings(settings).build().await.expect("client socket should build")
}
