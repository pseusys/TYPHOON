#[cfg(all(test, feature = "tokio"))]
#[path = "../../tests/session/server_health.rs"]
mod tests;

/// Server-side health check provider implementing the decay cycle.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;
use rand::Rng;

use crate::session::server::OutgoingRouter;
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailor::{IdentityType, ReturnCode, Tailor};
use crate::utils::unix_timestamp_ms;
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, WatchReceiver, WatchSender, create_watch, sleep};

/// Events produced when waiting for a client health check trigger.
enum ServerDecayEvent {
    Timeout,
    Terminated,
    Triggered(u32, u64),
}

/// Wait for a health check trigger from the client or a timeout.
async fn wait_for_trigger(timeout_ms: u64, trigger_rx: &mut WatchReceiver<(u32, u64)>) -> ServerDecayEvent {
    use futures::{future::select, future::Either, pin_mut};

    let sleep_fut = sleep(Duration::from_millis(timeout_ms));
    let recv_fut = trigger_rx.recv();
    pin_mut!(sleep_fut, recv_fut);

    match select(sleep_fut, recv_fut).await {
        Either::Left(_) => ServerDecayEvent::Timeout,
        Either::Right((Some((next_in, pn)), _)) => ServerDecayEvent::Triggered(next_in, pn),
        Either::Right((None, _)) => ServerDecayEvent::Terminated,
    }
}

/// Server-side health check provider.
/// Receives health check triggers from `process_incoming`, waits the client's requested
/// shadowride window, then sends a response echoing the client PN and a fresh server next_in.
/// Tracks whether the next client health check arrives within `server_next_in + timeout`;
/// retries up to MAX_RETRIES then calls `remove_session` to decay the connection.
pub(super) struct ServerHealthProvider {
    trigger_tx: WatchSender<(u32, u64)>,
}

impl ServerHealthProvider {
    pub(super) fn new<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, R: OutgoingRouter<T> + 'static>(
        router: Weak<R>,
        identity: T,
        settings: Arc<Settings<AE>>,
        initial_server_next_in: u32,
    ) -> Self {
        let (trigger_tx, trigger_rx) = create_watch();
        let executor = settings.executor().clone();
        executor.spawn(Self::timer_task(router, identity, settings, trigger_rx, initial_server_next_in));
        Self { trigger_tx }
    }

    /// Notify the provider that a health check arrived from the client.
    /// `client_next_in` is the TM field (client's requested response delay in ms).
    /// `client_pn` is the PN to echo back in the response.
    pub(super) fn feed_health_check(&self, client_next_in: u32, client_pn: u64) {
        self.trigger_tx.send((client_next_in, client_pn));
    }

    async fn timer_task<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, R: OutgoingRouter<T> + 'static>(
        router: Weak<R>,
        identity: T,
        settings: Arc<Settings<AE>>,
        mut trigger_rx: WatchReceiver<(u32, u64)>,
        initial_server_next_in: u32,
    ) {
        let timeout = settings.get(&TIMEOUT_DEFAULT).clamp(
            settings.get(&TIMEOUT_MIN),
            settings.get(&TIMEOUT_MAX),
        );
        // Initial wait: how long before the client should send its first health check after
        // receiving our handshake response (initial_server_next_in) plus decay tolerance.
        let mut current_timeout = initial_server_next_in as u64 + timeout;
        let mut retry_count: u64 = 0;

        'outer: loop {
            match wait_for_trigger(current_timeout, &mut trigger_rx).await {
                ServerDecayEvent::Triggered(client_next_in, client_pn) => {
                    retry_count = 0;

                    // Track the latest health check to respond to. If a newer HC arrives
                    // during the response delay, adopt its PN and delay and restart — the
                    // client has moved on and no longer expects the earlier response.
                    let mut response_pn = client_pn;
                    let mut delay_ms = (client_next_in as u64).clamp(
                        settings.get(&HEALTH_CHECK_NEXT_IN_MIN),
                        settings.get(&HEALTH_CHECK_NEXT_IN_MAX),
                    );

                    loop {
                        match wait_for_trigger(delay_ms, &mut trigger_rx).await {
                            ServerDecayEvent::Triggered(new_next_in, new_pn) => {
                                // Newer HC supersedes the pending one — restart delay.
                                response_pn = new_pn;
                                delay_ms = (new_next_in as u64).clamp(
                                    settings.get(&HEALTH_CHECK_NEXT_IN_MIN),
                                    settings.get(&HEALTH_CHECK_NEXT_IN_MAX),
                                );
                            }
                            ServerDecayEvent::Timeout => break,
                            ServerDecayEvent::Terminated => {
                                debug!("ServerHealthProvider: trigger channel closed, stopping");
                                break 'outer;
                            }
                        }
                    }

                    // Generate our next_in and send the response: PN = response_pn (echoed), TM = server_next_in.
                    let server_next_in = get_rng().gen_range(
                        settings.get(&HEALTH_CHECK_NEXT_IN_MIN)..=settings.get(&HEALTH_CHECK_NEXT_IN_MAX),
                    ) as u32;

                    let buf = settings.pool().allocate(Some(T::length()));
                    let response = Tailor::health_check(buf, &identity, server_next_in, response_pn).into_buffer();

                    let Some(r) = router.upgrade() else {
                        debug!("ServerHealthProvider: router dropped, stopping");
                        break 'outer;
                    };
                    r.route_packet(response, &identity).await;

                    // Expect the client's next health check within server_next_in + timeout.
                    current_timeout = server_next_in as u64 + timeout;
                    debug!("ServerHealthProvider: response sent (server_next_in={}ms), next timeout={}ms", server_next_in, current_timeout);
                }
                ServerDecayEvent::Timeout => {
                    retry_count += 1;
                    if retry_count < settings.get(&MAX_RETRIES) {
                        debug!("ServerHealthProvider: health check timeout, retry {}/{}", retry_count, settings.get(&MAX_RETRIES));
                        continue;
                    }
                    debug!("ServerHealthProvider: connection decayed after {} retries", retry_count);
                    if let Some(r) = router.upgrade() {
                        let pn = (unix_timestamp_ms() / 1000) as u64 * (1u64 << 32);
                        let buf = settings.pool().allocate(Some(T::length()));
                        let termination = Tailor::termination(buf, &identity, ReturnCode::ConnectionDecayed, pn).into_buffer();
                        r.route_packet(termination, &identity).await;
                        r.remove_session(&identity).await;
                    }
                    break 'outer;
                }
                ServerDecayEvent::Terminated => {
                    debug!("ServerHealthProvider: trigger channel closed, stopping");
                    break 'outer;
                }
            }
        }
    }
}
