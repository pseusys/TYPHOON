//! Wire tailer: the fixed-size, plaintext-then-encrypted metadata block at the end of every
//! TYPHOON packet. `flags`/`ReturnCode` define the packet-type and result-code bit fields;
//! `structure` defines the `Tailer` view itself plus the connection-handler traits.

mod flags;
mod structure;

pub use flags::{PacketFlags, ReturnCode};
pub use structure::{ClientConnectionHandler, IdentityType, ServerConnectionHandler, Tailer};
