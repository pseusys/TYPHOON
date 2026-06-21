/// Handshake-cost benchmarks:
///   "mceliece/keypair"  — Classic McEliece keypair generation (server one-time cost).
///   "mceliece/encap"    — Classic McEliece encapsulation (client per-handshake cost).
///   "mceliece/decap"    — Classic McEliece decapsulation (server per-handshake cost).
///   "x25519/keypair"    — X25519 ephemeral keypair generation (per-handshake baseline).
///   "x25519/ecdh"       — X25519 ephemeral Diffie-Hellman shared secret (per-handshake baseline).
///   "ed25519/sign"      — Ed25519 transcript signature (server per-handshake cost).
///   "handshake/end_to_end" — full client `build()` over UDP loopback against a live server,
///                            covering McEliece encap+decap, two-way X25519, Ed25519 sign+verify,
///                            tailer obfuscation, and the socket round trip.
///
/// The X25519 numbers anchor a "what if TYPHOON used a lattice/ECDH KEM instead" comparison;
/// the end-to-end measurement captures the realised cost the user observes per connection.
use std::net::UdpSocket;
use std::sync::Arc;

use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, Ciphertext, PublicKey as McEliecePublicKey, SecretKey as McElieceSecretKey, decapsulate, encapsulate, keypair_boxed};
use criterion::{Criterion, criterion_group, criterion_main};
use ed25519_dalek::{Signer, SigningKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::runtime::Runtime;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::FlowConfig;
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
const KEY_ENV_VAR: &str = "TYPHOON_TEST_SERVER_KEY_FAST";
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const KEY_ENV_VAR: &str = "TYPHOON_TEST_SERVER_KEY_FULL";

fn free_addr() -> std::net::SocketAddr {
    UdpSocket::bind("127.0.0.1:0").expect("OS should assign a free port").local_addr().unwrap()
}

fn load_or_generate_key() -> ServerKeyPair {
    if let Ok(path) = std::env::var(KEY_ENV_VAR) {
        let p = std::path::Path::new(&path);
        if p.exists()
            && let Ok(kp) = ServerKeyPair::load(p)
        {
            return kp;
        }
        let kp = ServerKeyPair::generate();
        let _ = kp.save(p);
        return kp;
    }
    ServerKeyPair::generate()
}

/// Generate a McEliece keypair once for the encap/decap sub-benchmarks.
/// Cached across iterations because keygen itself is benchmarked separately.
fn cached_mceliece_keypair() -> (McEliecePublicKey<'static>, McElieceSecretKey<'static>) {
    let mut rng = ChaCha20Rng::from_entropy();
    keypair_boxed(&mut rng)
}

// ───────────── Asymmetric primitives — micro-benchmarks ─────────────

fn bench_mceliece(c: &mut Criterion) {
    let mut group = c.benchmark_group("mceliece");

    group.bench_function("keypair", |b| {
        let mut rng = ChaCha20Rng::from_entropy();
        b.iter(|| {
            let (_pk, _sk) = keypair_boxed(&mut rng);
        });
    });

    let (public_key, secret_key) = cached_mceliece_keypair();

    group.bench_function("encap", |b| {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut shared = [0u8; CRYPTO_BYTES];
        b.iter(|| {
            let (_ct, _ss) = encapsulate(&public_key, &mut shared, &mut rng);
        });
    });

    // Pre-compute one ciphertext for decap iterations.
    let mut rng = ChaCha20Rng::from_entropy();
    let mut enc_shared = [0u8; CRYPTO_BYTES];
    let (ciphertext, _ss) = encapsulate(&public_key, &mut enc_shared, &mut rng);
    let ct_bytes: [u8; CRYPTO_CIPHERTEXTBYTES] = *ciphertext.as_array();

    group.bench_function("decap", |b| {
        let mut shared = [0u8; CRYPTO_BYTES];
        b.iter(|| {
            let ct = Ciphertext::from(ct_bytes);
            let _ss = decapsulate(&ct, &secret_key, &mut shared);
        });
    });

    group.finish();
}

fn bench_x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519");

    group.bench_function("keypair", |b| {
        b.iter(|| {
            let secret = EphemeralSecret::random_from_rng(ChaCha20Rng::from_entropy());
            let _public = X25519PublicKey::from(&secret);
        });
    });

    // For ECDH, prepare a peer public key once and pair a fresh ephemeral on every iteration —
    // simulates client computing the server-side ECDH on receipt of the server response.
    let peer_secret = EphemeralSecret::random_from_rng(ChaCha20Rng::from_entropy());
    let peer_public = X25519PublicKey::from(&peer_secret);

    group.bench_function("ecdh", |b| {
        b.iter_batched(
            || EphemeralSecret::random_from_rng(ChaCha20Rng::from_entropy()),
            |secret| {
                let _shared = secret.diffie_hellman(&peer_public);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519");

    // Ed25519 signing key; transcript hash size matches the typhoon handshake transcript.
    let mut secret_bytes = [0u8; 32];
    ChaCha20Rng::from_entropy().fill(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let mut transcript = [0u8; 32];
    rand::thread_rng().fill(&mut transcript);

    group.bench_function("sign", |b| {
        b.iter(|| {
            let _sig = signing_key.sign(&transcript);
        });
    });

    let signature = signing_key.sign(&transcript);
    let verifying_key = signing_key.verifying_key();

    group.bench_function("verify", |b| {
        b.iter(|| {
            verifying_key.verify_strict(&transcript, &signature).expect("verify");
        });
    });

    group.finish();
}

// ───────────── End-to-end TYPHOON handshake over UDP ─────────────

/// Full TYPHOON handshake round trip: a long-lived server accepts; we measure how long the
/// client takes to `build()`, which triggers the McEliece+X25519 handshake and the first
/// session-layer exchange.
fn bench_handshake_e2e(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("settings"));

    let addr = free_addr();
    let key_pair = load_or_generate_key();
    let certificate = key_pair.to_client_certificate(vec![addr]);

    let listener = Arc::new(rt.block_on(async { ListenerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(ServerFlowConfiguration::with_address(FlowConfig::random(&settings), addr)).with_settings(settings.clone()).build().await.expect("listener") }));
    rt.block_on(async { listener.start().await });

    // Drain every accepted client without doing anything — the handshake-cost benchmark
    // is what we care about; downstream data exchange is benched in roundtrip.rs.
    let listener_drain = listener.clone();
    rt.spawn(async move {
        loop {
            if let Ok(client) = listener_drain.accept().await {
                drop(client);
            } else {
                break;
            }
        }
    });

    let mut group = c.benchmark_group("handshake");
    group.sample_size(20);
    group.bench_function("end_to_end", |b| {
        b.to_async(&rt).iter(|| {
            let certificate = certificate.clone();
            let settings = settings.clone();
            async move {
                let _socket = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_flow_config(addr, FlowConfig::random(&settings)).with_settings(settings).build().await.expect("client handshake");
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_mceliece, bench_x25519, bench_ed25519, bench_handshake_e2e,);
criterion_main!(benches);
