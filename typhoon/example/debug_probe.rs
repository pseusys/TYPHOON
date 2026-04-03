use std::sync::Arc;

use env_logger;
use log::debug;

use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::debug::{DebugClientConnectionHandler, DebugMode, DebugServerConnectionHandler, run_debug};
use typhoon::defaults::{AsyncExecutor, DefaultExecutor};
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ListenerBuilder, ServerFlowConfiguration};

#[cfg(feature = "tokio")]
fn main() {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(run());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    futures::executor::block_on(run());
}

async fn run() {
    env_logger::init();

    let settings = Arc::new(
        SettingsBuilder::<DefaultExecutor>::new()
            .build()
            .expect("default settings should be valid"),
    );

    let server_addr = "127.0.0.1:19998".parse().expect("valid address");

    // Generate a server key pair and derive a client certificate.
    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![server_addr]);

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));

    // --- Start echo server ---
    let server_flow = ServerFlowConfiguration::with_address(flow_config, server_addr);
    let listener: Arc<_> = Arc::new(
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DebugServerConnectionHandler>::new(
            key_pair,
            DebugServerConnectionHandler,
        )
        .add_flow(server_flow)
        .with_settings(settings.clone())
        .build()
        .await
        .expect("listener should build"),
    );
    listener.start().await;
    println!("Debug echo server listening on {}", server_addr);

    // Spawn a per-client echo loop for every connecting debug client.
    let listener_handle = listener.clone();
    let inner_settings = settings.clone();
    settings.executor().spawn(async move {
        loop {
            let Ok(client) = listener_handle.accept().await else { break };
            // Echo every packet back verbatim.
            inner_settings.executor().spawn(async move {
                let mut echo_count = 0usize;
                loop {
                    let data = match client.receive_bytes().await {
                        Ok(d) => d,
                        Err(e) => {
                            debug!("echo loop: receive error after {} echo(es): {}", echo_count, e);
                            break;
                        }
                    };
                    echo_count += 1;
                    debug!("echo loop: received #{} ({} bytes), forwarding", echo_count, data.len());
                    if let Err(e) = client.send_bytes(&data).await {
                        debug!("echo loop: send error on echo #{}: {}", echo_count, e);
                        break;
                    }
                }
                debug!("echo loop: exited after {} echo(es)", echo_count);
            });
        }
    });

    // --- Run reachability probe ---
    println!("\n=== Reachability ===");
    let result = run_debug(certificate.clone(), DebugMode::Reachability, settings.clone()).await;
    println!("  reachable:        {:?}", result.reachable);
    println!("  packets sent:     {}", result.packets_sent);
    println!("  packets received: {}", result.packets_received);

    // --- Run return-time (RTT) probe ---
    println!("\n=== Return Time ===");
    let result = run_debug(certificate.clone(), DebugMode::ReturnTime, settings.clone()).await;
    println!("  rtt_ms:           {:?}", result.rtt_ms);
    println!("  packets sent:     {}", result.packets_sent);
    println!("  packets received: {}", result.packets_received);

    // --- Run throughput probe ---
    println!("\n=== Throughput ===");
    let result = run_debug(certificate.clone(), DebugMode::Throughput, settings.clone()).await;
    println!("  throughput_bps:   {:?}", result.throughput_bps);
    println!("  packets sent:     {}", result.packets_sent);
    println!("  packets received: {}", result.packets_received);
}

// Silence the unused-import warning when the `debug` feature is not active.
#[allow(dead_code)]
fn _require_debug_handler(_: DebugClientConnectionHandler) {}
