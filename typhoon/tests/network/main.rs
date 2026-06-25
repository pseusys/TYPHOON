/// Network integration tests for the TYPHOON protocol stack.
///
/// Each module exercises a distinct scenario through the full
/// socket → session → flow → decoy chain.
mod common;

mod client_pool;
mod decoy;
mod echo;
mod errors;
mod handshake_replay;
mod identity_rejection;
mod multi_client;
mod multi_flow;
