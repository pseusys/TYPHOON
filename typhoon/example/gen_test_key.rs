/// Generate a server key pair and save it to a file.
///
/// Used by `test_matrix.sh` to pre-generate key material before running tests,
/// avoiding expensive McEliece key generation on every test binary invocation.
///
/// Usage:
///   cargo run --example gen_test_key --no-default-features \
///             --features fast_software,server,tokio -- path/to/server.key
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: gen_test_key <output_path>");

    typhoon::certificate::ServerKeyPair::generate()
        .save(&path)
        .unwrap_or_else(|e| panic!("failed to save key pair to {path}: {e}"));

    println!("Server key pair written to {path}");
}
