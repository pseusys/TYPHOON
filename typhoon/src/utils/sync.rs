use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "tokio")] {
        pub use tokio::sync::mpsc::{Sender, Receiver, WeakSender, channel};
        pub use tokio::sync::RwLock;
    } else if #[cfg(feature = "async-std")] {
        pub use async_channel::{Sender, Receiver, WeakSender, bounded as channel};
        pub use async_lock::RwLock;
    }
}
