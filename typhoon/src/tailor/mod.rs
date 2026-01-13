mod codec;
mod flags;
mod structure;

pub use codec::{
    append_encrypted_tailor, extract_encrypted_tailor, TailorCodec, ENCRYPTED_TAILOR_SIZE,
    TAILOR_ENCRYPTION_OVERHEAD,
};
pub use flags::{PacketFlags, ReturnCode};
pub use structure::Tailor;
