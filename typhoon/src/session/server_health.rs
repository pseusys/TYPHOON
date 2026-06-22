#[cfg(all(test, feature = "tokio"))]
#[path = "../../tests/session/server_health.rs"]
mod tests;

/// Server-side health check provider implementing the decay cycle.
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures::future::{Either, select};
use futures::pin_mut;
use log::debug;
use rand::Rng;

use crate::session::SessionControllerError;
use crate::session::common::ShadowrideEvent;
use crate::session::rtt::RttEstimator;
use crate::session::server::OutgoingRouter;
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailer::{IdentityType, PacketFlags, ReturnCode, Tailer};
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, Mutex, WatchReceiver, WatchSender, create_watch, sleep};
use crate::utils::unix_timestamp_ms;

/// Events produced when waiting for a client health check trigger.
enum ServerDecayEvent {
    Timeout,
    Terminated,
    Triggered(u32, u64, u128),
}

/// Wait for a health check trigger from the client or a timeout.
async fn wait_for_trigger(timeout_ms: u64, trigger_rx: &mut WatchReceiver<(u32, u64, u128)>) -> ServerDecayEvent {
    let sleep_fut = sleep(Duration::from_millis(timeout_ms));
    let recv_fut = trigger_rx.recv();
    pin_mut!(sleep_fut, recv_fut);

    match select(sleep_fut, recv_fut).await {
        Either::Left(_) => ServerDecayEvent::Timeout,
        Either::Right((Some((next_in, pn, receive_time)), _)) => ServerDecayEvent::Triggered(next_in, pn, receive_time),
        Either::Right((None, _)) => ServerDecayEvent::Terminated,
    }
}

/// Wait for a shadowride consumption signal or a timeout.
async fn wait_for_shadowride(timeout_ms: u64, shadowride_rx: &mut WatchReceiver<()>) -> ShadowrideEvent {
    let sleep_fut = sleep(Duration::from_millis(timeout_ms));
    let recv_fut = shadowride_rx.recv();
    pin_mut!(sleep_fut, recv_fut);

    match select(sleep_fut, recv_fut).await {
        Either::Left(_) => ShadowrideEvent::Timeout,
        Either::Right((Some(()), _)) => ShadowrideEvent::Shadowridden,
        Either::Right((None, _)) => ShadowrideEvent::Terminated,
    }
}

/// Server-side health check provider.
/// Receives health check triggers from `process_incoming`, waits the client's requested
/// shadowride window, then sends a response echoing the client PN and a fresh server next_in.
/// Tracks whether the next client health check arrives within `server_next_in + timeout`;
/// retries up to MAX_RETRIES then calls `remove_session` to decay the connection.
pub(super) struct ServerHealthProvider {
    trigger_tx: WatchSender<(u32, u64, u128)>,
    shadowride_tx: WatchSender<()>,
    /// Pending shadowride data: (PN, next_in) to attach to the next outgoing data packet.
    shadowride_pending: Arc<Mutex<Option<(u64, u32)>>>,
}

impl ServerHealthProvider {
    pub(super) fn new<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static>(router: Weak<dyn OutgoingRouter<T>>, identity: T, settings: Arc<Settings<AE>>, initial_server_next_in: u32, handshake_pn: u64) -> Self {
        let (trigger_tx, trigger_rx) = create_watch();
        let (shadowride_tx, shadowride_rx) = create_watch();
        let shadowride_pending = Arc::new(Mutex::new(None));
        let executor = settings.executor().clone();
        executor.spawn(Self::timer_task(router, identity, settings, trigger_rx, shadowride_rx, Arc::clone(&shadowride_pending), initial_server_next_in, handshake_pn));
        Self {
            trigger_tx,
            shadowride_tx,
            shadowride_pending,
        }
    }

    /// Notify the provider that a health check arrived from the client.
    /// `client_next_in` is the TM field (client's requested response delay in ms).
    /// `client_pn` is the PN to echo back in the response.
    pub(super) fn feed_health_check(&self, client_next_in: u32, client_pn: u64) {
        let receive_time = unix_timestamp_ms();
        self.trigger_tx.send((client_next_in, client_pn, receive_time));
    }

    /// Called before a data packet is sent. May modify the tailer for shadowriding.
    pub(super) async fn feed_output<T: IdentityType>(&self, tailer: Tailer<T>) -> Result<(), SessionControllerError> {
        if tailer.flags().contains(PacketFlags::HEALTH_CHECK) {
            return Ok(());
        }

        let shadowridden = {
            let mut pending = self.shadowride_pending.lock().await;
            if let Some((pn, next_in)) = pending.take() {
                tailer.set_flags(tailer.flags() | PacketFlags::HEALTH_CHECK);
                tailer.set_time(next_in);
                tailer.set_packet_number_raw(pn);
                debug!("ServerHealthProvider: health check shadowridden onto data packet (PN={pn:#018x})");
                true
            } else {
                false
            }
        };

        if shadowridden && !self.shadowride_tx.send(()) {
            return Err(SessionControllerError::HealthProviderDied);
        }

        Ok(())
    }

    async fn timer_task<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static>(router: Weak<dyn OutgoingRouter<T>>, identity: T, settings: Arc<Settings<AE>>, mut trigger_rx: WatchReceiver<(u32, u64, u128)>, mut shadowride_rx: WatchReceiver<()>, shadowride_pending: Arc<Mutex<Option<(u64, u32)>>>, initial_server_next_in: u32, handshake_pn: u64) {
        let mut rtt = RttEstimator::new();
        let mut last_sent_time: u128 = 0;
        let mut last_sent_next_in: u32 = 0;
        // Initial wait: how long before the client should send its first health check after
        // receiving our handshake response (initial_server_next_in) plus decay tolerance.
        let mut current_timeout = initial_server_next_in as u64 + rtt.compute_timeout(&settings);
        let mut retry_count: u64 = 0;

        'outer: loop {
            match wait_for_trigger(current_timeout, &mut trigger_rx).await {
                ServerDecayEvent::Triggered(client_next_in, client_pn, receive_time) => {
                    retry_count = 0;

                    // Update RTT from the gap between our last response and this trigger, minus
                    // the intentional delay we asked the client to wait (mirrors
                    // ClientHealthProvider::update_rtt, just measured from the other end).
                    if last_sent_time > 0 {
                        rtt.update(&settings, receive_time, last_sent_time, last_sent_next_in);
                    }

                    // Track the latest health check to respond to. If a newer HC arrives
                    // during the response delay, adopt its PN and delay and restart — the
                    // client has moved on and no longer expects the earlier response.
                    let mut response_pn = client_pn;
                    let mut delay_ms = (client_next_in as u64).clamp(settings.get(&HEALTH_CHECK_NEXT_IN_MIN), settings.get(&HEALTH_CHECK_NEXT_IN_MAX));

                    loop {
                        match wait_for_trigger(delay_ms, &mut trigger_rx).await {
                            ServerDecayEvent::Triggered(new_next_in, new_pn, _) => {
                                // Newer HC supersedes the pending one — restart delay.
                                response_pn = new_pn;
                                delay_ms = (new_next_in as u64).clamp(settings.get(&HEALTH_CHECK_NEXT_IN_MIN), settings.get(&HEALTH_CHECK_NEXT_IN_MAX));
                            }
                            ServerDecayEvent::Timeout => break,
                            ServerDecayEvent::Terminated => {
                                debug!("ServerHealthProvider: trigger channel closed, stopping");
                                break 'outer;
                            }
                        }
                    }

                    // Generate our next_in, then try to shadowride the response onto an outgoing
                    // data packet (mirrors ClientHealthProvider::send_or_shadowride) before
                    // falling back to a dedicated packet.
                    let server_next_in = get_rng().gen_range(settings.get(&HEALTH_CHECK_NEXT_IN_MIN)..=settings.get(&HEALTH_CHECK_NEXT_IN_MAX)) as u32;

                    {
                        let mut pending = shadowride_pending.lock().await;
                        *pending = Some((response_pn, server_next_in));
                    }

                    let shadowride_window = (rtt.smooth_or_default(&settings) * 2.0).max(1.0) as u64;
                    match wait_for_shadowride(shadowride_window, &mut shadowride_rx).await {
                        ShadowrideEvent::Shadowridden => {
                            last_sent_time = unix_timestamp_ms();
                            last_sent_next_in = server_next_in;
                            debug!("ServerHealthProvider: health check shadowridden onto data packet (PN={response_pn:#018x})");
                        }
                        ShadowrideEvent::Timeout => {
                            {
                                let mut pending = shadowride_pending.lock().await;
                                *pending = None;
                            }
                            let buf = settings.pool().allocate(Some(T::length()));
                            let response = Tailer::health_check(buf, &identity, server_next_in, response_pn).into_buffer();

                            let Some(r) = router.upgrade() else {
                                debug!("ServerHealthProvider: router dropped, stopping");
                                break 'outer;
                            };
                            r.route_packet(response, &identity).await;
                            last_sent_time = unix_timestamp_ms();
                            last_sent_next_in = server_next_in;
                        }
                        ShadowrideEvent::Terminated => {
                            debug!("ServerHealthProvider: shadowride channel closed, stopping");
                            break 'outer;
                        }
                    }

                    // Expect the client's next health check within server_next_in + timeout.
                    current_timeout = server_next_in as u64 + rtt.compute_timeout(&settings);
                    debug!("ServerHealthProvider: response sent (server_next_in={server_next_in}ms), next timeout={current_timeout}ms");
                }
                ServerDecayEvent::Timeout => {
                    retry_count += 1;
                    if retry_count < settings.get(&MAX_RETRIES) {
                        debug!("ServerHealthProvider: health check timeout, retry {}/{}", retry_count, settings.get(&MAX_RETRIES));
                        continue;
                    }
                    debug!("ServerHealthProvider: connection decayed after {retry_count} retries");
                    if let Some(r) = router.upgrade() {
                        if r.is_current_session(&identity, handshake_pn).await {
                            let pn = (unix_timestamp_ms() / 1000) as u64;
                            let buf = settings.pool().allocate(Some(T::length()));
                            let termination = Tailer::termination(buf, &identity, ReturnCode::ConnectionDecayed, pn).into_buffer();
                            r.route_packet(termination, &identity).await;
                            r.remove_session(&identity, handshake_pn).await;
                        } else {
                            debug!("ServerHealthProvider: session already replaced, skipping decay cleanup");
                        }
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
