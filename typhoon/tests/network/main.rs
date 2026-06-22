/// Network integration tests for the TYPHOON protocol stack.
///
/// Each module exercises a distinct scenario through the full
/// socket → session → flow → decoy chain.
mod common;

mod decoy;
mod echo;
mod errors;
mod handshake_replay;
mod multi_client;
mod multi_flow;
