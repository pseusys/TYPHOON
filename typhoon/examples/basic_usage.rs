//! Basic usage example for TYPHOON protocol.
//!
//! This example demonstrates:
//! 1. Low-level packet construction with existing modules
//! 2. Tailor structure and serialization
//! 3. Health check and decay cycle
//! 4. Flow envelope with obfuscation
//!
//! NOTE: High-level TyphoonListener/TyphoonClient are not yet implemented.
//! See the end of this file for the intended high-level API.

use typhoon::bytes::ByteBuffer;
use typhoon::constants::tailor::TYPHOON_ID_LENGTH;
use typhoon::crypto::symmetric::Symmetric;
use typhoon::error::{TyphoonError, TyphoonResult};
use typhoon::flow::{BaseFlowManager, Envelope, FlowConfig, FlowController};
use typhoon::session::{BaseSessionManager, DecayCycle, RttTracker};
use typhoon::tailor::{ReturnCode, Tailor, TailorCodec, ENCRYPTED_TAILOR_SIZE};

// ============================================================================
// TAILOR STRUCTURE EXAMPLE
// ============================================================================

/// Example showing different tailor types and their fields.
fn tailor_example() {
    println!("--- Tailor Structure Examples ---\n");

    let identity: [u8; TYPHOON_ID_LENGTH] = [0xAB; TYPHOON_ID_LENGTH];

    // Data packet: carries encrypted payload
    let data_tailor = Tailor::data(identity, 1024, 0x12345678_00000001);
    println!(
        "Data tailor:\n  flags={:?}\n  payload_len={} bytes\n  packet_number=0x{:016x}",
        data_tailor.flags, data_tailor.payload_length, data_tailor.packet_number
    );

    // Health check packet: keep-alive with timing info
    let health_tailor = Tailor::health_check(identity, 5000, 0x12345678_00000002);
    println!(
        "\nHealth check:\n  flags={:?}\n  next_in={} ms",
        health_tailor.flags, health_tailor.time
    );

    // Shadowride packet: data + health check combined (saves bandwidth)
    let shadow_tailor = Tailor::shadowride(identity, 512, 3000, 0x12345678_00000003);
    println!(
        "\nShadowride:\n  flags={:?}\n  payload_len={} bytes\n  next_in={} ms",
        shadow_tailor.flags, shadow_tailor.payload_length, shadow_tailor.time
    );

    // Handshake packet: initial connection establishment
    let handshake_tailor = Tailor::handshake(identity, 0x01, 10000, 0x12345678_00000004);
    println!(
        "\nHandshake:\n  flags={:?}\n  code=0x{:02x}",
        handshake_tailor.flags, handshake_tailor.code
    );

    // Termination packet: graceful connection close
    let term_tailor = Tailor::termination(identity, ReturnCode::Success, 0x12345678_00000005);
    println!(
        "\nTermination:\n  flags={:?}\n  return_code={:?}",
        term_tailor.flags,
        term_tailor.return_code()
    );

    // Decoy packet: fake traffic for obfuscation
    let decoy_tailor = Tailor::decoy(identity, 0x12345678_00000006);
    println!("\nDecoy:\n  flags={:?}", decoy_tailor.flags);

    // Serialize to wire format
    let buffer = data_tailor.to_buffer();
    println!("\nSerialized tailor: {} bytes (fixed size)", buffer.len());

    // Deserialize back
    let restored = Tailor::from_buffer(&buffer).unwrap();
    assert_eq!(restored.flags, data_tailor.flags);
    assert_eq!(restored.identity, data_tailor.identity);
    println!("Deserialization: OK");
}

// ============================================================================
// HEALTH CHECK / DECAY CYCLE EXAMPLE
// ============================================================================

/// Example showing RTT tracking and decay cycle for adaptive timing.
fn health_check_example() {
    println!("\n--- Health Check / Decay Cycle ---\n");

    // RTT tracking with EWMA (Exponentially Weighted Moving Average)
    let rtt_tracker = RttTracker::new();

    // Simulate RTT measurements
    rtt_tracker.update(50); // 50ms
    rtt_tracker.update(55); // 55ms
    rtt_tracker.update(48); // 48ms
    rtt_tracker.update(52); // 52ms

    println!("RTT Tracker:");
    println!("  Smooth RTT (SRTT): {} ms", rtt_tracker.get_rtt());
    println!("  RTT Variance: {} ms", rtt_tracker.get_variance());
    println!("  Calculated Timeout: {} ms", rtt_tracker.get_timeout());

    // Decay cycle: manages health check protocol state machine
    // Used for adaptive keep-alive timing based on RTT
    let rtt_arc = std::sync::Arc::new(RttTracker::new());
    let (decay, _shadowride_done_tx, _shadowride_req_rx) = DecayCycle::new(rtt_arc);

    println!("\nDecay Cycle (health check state machine):");
    println!("  Initial state: {:?}", decay.state());
    println!("  Is active: {}", decay.is_active());
    println!("  Retry count: {}", decay.retry_count());

    // Simulate handshake completion
    decay.handshake_complete();
    println!("  After handshake: {:?}", decay.state());

    // Simulate receiving a health check
    let received = decay.process_health_check(0x12345678_00000001, 5000);
    println!("  After receiving health check: {:?} (processed: {})", decay.state(), received);

    // Generate next_in value for health checks
    let next_in = DecayCycle::generate_next_in();
    println!("  Generated next_in: {} ms", next_in);
}

// ============================================================================
// LOW-LEVEL PACKET CONSTRUCTION
// ============================================================================

/// Example showing low-level packet construction with encryption.
async fn packet_construction_example() -> TyphoonResult<()> {
    println!("\n--- Low-Level Packet Construction ---\n");

    // In real usage, these keys come from the handshake
    let obfs_key = ByteBuffer::from(&[0x42u8; 32]);
    let session_key = ByteBuffer::from(&[0x24u8; 32]);

    // Create session cipher from session key
    let session_cipher =
        Symmetric::new(&session_key).map_err(|e| TyphoonError::KeyDerivationFailed(e.to_string()))?;

    // Client identity (UUID)
    let identity: [u8; TYPHOON_ID_LENGTH] = [0xAB; TYPHOON_ID_LENGTH];

    // Create session manager
    let session = BaseSessionManager::new(identity, session_cipher);
    println!("Session created:");
    println!("  ID: {:02x?}...", &identity[..4]);
    println!("  Active: {}", session.is_active());

    // Create tailor codec for tailor encryption
    let mut tailor_codec = TailorCodec::new(&obfs_key)?;

    // === CONSTRUCTING A DATA PACKET ===
    println!("\nConstructing data packet:");

    // 1. Prepare payload with capacity for encryption overhead
    // Encryption prepends nonce (24 bytes for XChaCha20) and appends tag (16 bytes)
    let payload_data = b"Hello, TYPHOON!";
    let payload = ByteBuffer::from_slice_with_capacity(payload_data, 24, 16);
    println!("  Payload: {} bytes", payload.len());

    // 2. Encrypt payload with session cipher
    let encrypted_payload = session.encrypt_payload(payload)?;
    println!("  Encrypted payload: {} bytes", encrypted_payload.len());

    // 3. Create tailor with packet metadata
    let packet_number = session.next_packet_number();
    let tailor = Tailor::data(identity, encrypted_payload.len() as u16, packet_number);
    println!(
        "  Tailor: flags={:?}, pn=0x{:016x}",
        tailor.flags, tailor.packet_number
    );

    // 4. Encrypt tailor (uses obfuscation key + session key for dual auth)
    let encrypted_tailor = tailor_codec.encrypt(&tailor, &session_key)?;
    println!("  Encrypted tailor: {} bytes", encrypted_tailor.len());

    // 5. Assemble packet: [encrypted_payload] || [encrypted_tailor]
    // Need to allocate with capacity for both components
    let packet = ByteBuffer::from_slice_with_capacity(encrypted_payload.slice(), 0, encrypted_tailor.len())
        .append_buf(&encrypted_tailor);
    println!("  Final packet: {} bytes", packet.len());

    // === PARSING A RECEIVED PACKET ===
    println!("\nParsing received packet:");

    // 1. Split tailor from end
    let (body, enc_tailor) = packet.split_buf(packet.len() - ENCRYPTED_TAILOR_SIZE);
    println!(
        "  Body: {} bytes, Tailor: {} bytes",
        body.len(),
        enc_tailor.len()
    );

    // 2. Decrypt tailor (server would do two-step for demux)
    let decrypted_tailor = tailor_codec.decrypt(enc_tailor, &session_key)?;
    println!(
        "  Decrypted tailor: flags={:?}, payload_len={}",
        decrypted_tailor.flags, decrypted_tailor.payload_length
    );

    // 3. Decrypt payload
    let decrypted_payload = session.decrypt_payload(body)?;
    println!(
        "  Decrypted payload: {:?}",
        String::from_utf8_lossy(decrypted_payload.slice())
    );

    Ok(())
}

// ============================================================================
// FLOW ENVELOPE EXAMPLE
// ============================================================================

/// Example showing packet envelope with fake headers/bodies.
async fn envelope_example() -> TyphoonResult<()> {
    println!("\n--- Flow Envelope (Obfuscation) ---\n");

    // Create flow with obfuscation enabled
    let config = FlowConfig::new("0.0.0.0:0".parse().unwrap());
    let flow = BaseFlowManager::new(config).await?;

    println!("Flow bound to: {}", flow.local_addr()?);

    // Simulated encrypted payload and tailor
    let encrypted_payload = ByteBuffer::from(&[0x11u8; 100]);
    let encrypted_tailor = ByteBuffer::from(&[0x22u8; ENCRYPTED_TAILOR_SIZE]);

    // Wrap with async envelope (generates random fake header/body)
    let packet = flow
        .wrap_envelope_async(encrypted_payload.copy(), encrypted_tailor.copy())
        .await?;
    println!(
        "Wrapped packet: {} bytes (payload=100, tailor={}, obfuscation={})",
        packet.len(),
        ENCRYPTED_TAILOR_SIZE,
        packet.len() - 100 - ENCRYPTED_TAILOR_SIZE
    );

    // Unwrap to extract tailor (strips fake header/body)
    let (body, extracted_tailor) = flow.unwrap_envelope(packet)?;
    println!(
        "Unwrapped: body={} bytes, tailor={} bytes",
        body.len(),
        extracted_tailor.len()
    );

    // Manual envelope construction (no obfuscation)
    let envelope = Envelope::payload_only(
        ByteBuffer::from(&[0x33u8; 50]),
        ByteBuffer::from(&[0x44u8; ENCRYPTED_TAILOR_SIZE]),
    )?;
    let manual_packet = envelope.into_buffer();
    println!(
        "Manual packet (no obfuscation): {} bytes",
        manual_packet.len()
    );

    Ok(())
}

// ============================================================================
// INTENDED HIGH-LEVEL API (NOT YET IMPLEMENTED)
// ============================================================================

/// This shows the intended high-level API once server/client are implemented.
///
/// ```rust,ignore
/// use typhoon::server::TyphoonListener;
/// use typhoon::client::TyphoonClient;
///
/// // === SERVER ===
/// async fn run_server() -> TyphoonResult<()> {
///     // Load or generate server secret
///     let server_secret = ServerSecret::generate()?;
///
///     // Create listener on multiple ports (flows)
///     let listener = TyphoonListener::builder()
///         .secret(server_secret)
///         .bind("0.0.0.0:8443")?
///         .bind("0.0.0.0:8444")?
///         .build()?;
///
///     // Export certificate for clients
///     listener.certificate().save("server.cert")?;
///
///     // Accept connections
///     loop {
///         let (session, addr) = listener.accept().await?;
///
///         tokio::spawn(async move {
///             loop {
///                 match session.recv().await {
///                     Ok(data) => {
///                         // Echo back
///                         session.send(data).await?;
///                     }
///                     Err(TyphoonError::ConnectionClosed) => break,
///                     Err(e) => eprintln!("Error: {e}"),
///                 }
///             }
///         });
///     }
/// }
///
/// // === CLIENT ===
/// async fn run_client() -> TyphoonResult<()> {
///     // Load server certificate
///     let certificate = Certificate::load("server.cert")?;
///
///     // Connect to server
///     let client = TyphoonClient::connect(certificate, "127.0.0.1:8443").await?;
///
///     // Send data
///     client.send(b"Hello, server!").await?;
///
///     // Receive response
///     let response = client.recv().await?;
///     println!("Server said: {:?}", response);
///
///     // Close connection gracefully
///     client.close().await?;
///
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
fn intended_api_docs() {}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() -> TyphoonResult<()> {
    println!("=== TYPHOON Protocol Usage Examples ===\n");

    tailor_example();
    health_check_example();
    packet_construction_example().await?;
    envelope_example().await?;

    println!("\n=== Examples Complete ===");
    println!("\nNote: High-level TyphoonListener/TyphoonClient APIs are not yet implemented.");
    println!("See the source code comments for the intended API design.");

    Ok(())
}
