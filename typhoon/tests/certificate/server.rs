use std::env::var;
use std::path::Path;

use crate::certificate::ClientCertificate;
use super::{ServerKeyPair, ServerSecret};

impl ServerKeyPair {
    /// Load from the mode-appropriate env var path when set; otherwise generate (and save).
    ///
    /// Set `TYPHOON_TEST_SERVER_KEY_FAST` (fast_software/fast_hardware) or
    /// `TYPHOON_TEST_SERVER_KEY_FULL` (full_software/full_hardware) to a file path before
    /// running tests to skip expensive McEliece key generation.
    pub fn for_tests() -> Self {
        let env_var = if cfg!(any(feature = "fast_software", feature = "fast_hardware")) {
            "TYPHOON_TEST_SERVER_KEY_FAST"
        } else {
            "TYPHOON_TEST_SERVER_KEY_FULL"
        };

        if let Ok(path) = var(env_var) {
            let p = Path::new(&path);
            if p.exists() {
                if let Ok(kp) = Self::load(p) {
                    return kp;
                }
            }
            let kp = Self::generate();
            let _ = kp.save(p);
            kp
        } else {
            Self::generate()
        }
    }

    /// Create a matched (ClientCertificate, ServerSecret) pair for use in tests.
    /// Calls `for_tests()` once so both sides share the same key material.
    #[cfg(all(feature = "client", feature = "server"))]
    pub(crate) fn for_tests_pair() -> (ClientCertificate, ServerSecret<'static>) {
        let kp = Self::for_tests();
        let cert = kp.to_client_certificate(vec![]);
        let secret = kp.into_server_secret();
        (cert, secret)
    }

    pub(crate) fn epk_bytes(&self) -> &[u8] {
        self.epk.as_array()
    }

    pub(crate) fn esk_bytes(&self) -> &[u8] {
        self.esk.as_array()
    }

    pub(crate) fn vsk_bytes(&self) -> [u8; 32] {
        self.vsk.to_bytes()
    }

    pub(crate) fn verifying_key_bytes(&self) -> [u8; 32] {
        self.vsk.verifying_key().to_bytes()
    }

    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn obfs_bytes(&self) -> &[u8] {
        self.obfs.as_ref()
    }

    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn opk_bytes(&self) -> &[u8] {
        self.opk.as_bytes()
    }

    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn osk_bytes(&self) -> [u8; 32] {
        self.osk.to_bytes()
    }
}
