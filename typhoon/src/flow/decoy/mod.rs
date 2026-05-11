//! Decoy traffic communication modes for flow obfuscation.
//!
//! The runtime trait [`DecoyProvider`] (made object-safe via `async-trait`) drives the three
//! callbacks: `start`, `feed_input`, and `feed_output`. The construction trait
//! [`DecoyCommunicationMode`] extends it with `new()` and is the target of [`decoy_factory`].
//!
//! A [`DecoyFactory`] is a type-erased `Arc<dyn Fn(…) -> Box<dyn DecoyProvider>>` so that
//! different flows or users can hold different concrete provider types at runtime.
//! Use [`decoy_factory::<T, AE, DP>()`](decoy_factory) to wrap a concrete type, or
//! [`random_decoy_factory()`] for the default behavior (random selection per invocation).
mod common;
mod heavy;
mod noisy;
mod simple;
mod smooth;
mod sparse;

use std::sync::{Arc, Weak};

pub use common::{DecoyCommunicationMode, DecoyFlowSender, DecoyProvider};
pub use heavy::HeavyDecoyProvider;
use log::info;
pub use noisy::NoisyDecoyProvider;
pub use crate::tailor::{IdentityType, PacketFlags, Tailor};
pub use simple::SimpleDecoyProvider;
pub use smooth::SmoothDecoyProvider;
pub use sparse::SparseDecoyProvider;

use crate::settings::Settings;
use crate::settings::keys::{DECOY_PROVIDER_WEIGHT_HEAVY, DECOY_PROVIDER_WEIGHT_NOISY, DECOY_PROVIDER_WEIGHT_SIMPLE, DECOY_PROVIDER_WEIGHT_SMOOTH, DECOY_PROVIDER_WEIGHT_SPARSE};
use crate::utils::sync::AsyncExecutor;
use crate::weighted_random;

/// A factory that constructs a `Box<dyn DecoyProvider>` for a given identity and flow manager.
pub type DecoyFactory<T, AE> = Arc<dyn Fn(Weak<dyn DecoyFlowSender>, Arc<Settings<AE>>, T) -> Box<dyn DecoyProvider> + Send + Sync>;

/// Lift a concrete `DecoyCommunicationMode` type into a `DecoyFactory`.
pub fn decoy_factory<T, AE, DP>() -> DecoyFactory<T, AE>
where
    T: IdentityType + Clone + 'static,
    AE: AsyncExecutor + 'static,
    DP: DecoyCommunicationMode<T, AE> + 'static,
{
    Arc::new(|manager, settings, identity| {
        info!("decoy provider: {}", <DP as DecoyCommunicationMode<T, AE>>::name());
        Box::new(DP::new(manager, settings, identity))
    })
}

/// Factory that randomly selects one of the five built-in decoy providers per invocation,
/// weighted by the `DECOY_PROVIDER_WEIGHT_*` settings.
pub fn random_decoy_factory<T, AE>() -> DecoyFactory<T, AE>
where
    T: IdentityType + Clone + 'static,
    AE: AsyncExecutor + 'static,
{
    Arc::new(|manager, settings, identity| {
        weighted_random! {
            settings.get(&DECOY_PROVIDER_WEIGHT_SIMPLE) => {
                info!("decoy provider: {}", <SimpleDecoyProvider as DecoyCommunicationMode<T, AE>>::name());
                Box::new(SimpleDecoyProvider::new(manager, settings, identity)) as Box<dyn DecoyProvider>
            },
            settings.get(&DECOY_PROVIDER_WEIGHT_SPARSE) => {
                info!("decoy provider: {}", <SparseDecoyProvider<T, AE> as DecoyCommunicationMode<T, AE>>::name());
                Box::new(SparseDecoyProvider::new(manager, settings, identity)) as Box<dyn DecoyProvider>
            },
            settings.get(&DECOY_PROVIDER_WEIGHT_NOISY) => {
                info!("decoy provider: {}", <NoisyDecoyProvider<T, AE> as DecoyCommunicationMode<T, AE>>::name());
                Box::new(NoisyDecoyProvider::new(manager, settings, identity)) as Box<dyn DecoyProvider>
            },
            settings.get(&DECOY_PROVIDER_WEIGHT_SMOOTH) => {
                info!("decoy provider: {}", <SmoothDecoyProvider<T, AE> as DecoyCommunicationMode<T, AE>>::name());
                Box::new(SmoothDecoyProvider::new(manager, settings, identity)) as Box<dyn DecoyProvider>
            },
            settings.get(&DECOY_PROVIDER_WEIGHT_HEAVY) => {
                info!("decoy provider: {}", <HeavyDecoyProvider<T, AE> as DecoyCommunicationMode<T, AE>>::name());
                Box::new(HeavyDecoyProvider::new(manager, settings, identity)) as Box<dyn DecoyProvider>
            },
        }
    })
}
