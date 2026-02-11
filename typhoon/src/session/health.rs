use std::marker::PhantomData;
/// Health check provider implementing the decay cycle for connection liveness tracking.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;
use rand::Rng;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::session::common::SessionManager;
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailor::{IdentityType, PacketFlags, Tailor};
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, FuturePool, RwLock, Sender, Receiver, sleep};
use crate::utils::time::unix_timestamp_ms;

/// Events produced during the decay cycle.
enum DecayEvent {
    Timeout,
    ResponseReceived { server_next_in: u32, receive_time: u128 },
}

/// Internal state shared between the timer task and feed methods.
struct HealthState<T: IdentityType, AE: AsyncExecutor> {
    settings: Arc<Settings<AE>>,
    /// EWMA smoothed RTT in milliseconds.
    smooth_rtt: Option<f64>,
    /// RTT variance in milliseconds.
    rtt_variance: Option<f64>,
    /// Incremental packet number counter (lower 32 bits of PN).
    incremental_counter: u32,
    /// Current retry count.
    retry_count: u64,
    /// Timestamp when the last health check was sent.
    last_sent_time: u128,
    /// The next_in value of the last sent health check (client's TM).
    last_sent_next_in: u32,
    /// The PN of the current outstanding health check.
    current_pn: u64,
    /// Pending shadowride data: (PN, next_in) to attach to next data packet.
    shadowride_pending: Option<(u64, u32)>,
    /// Client identity bytes.
    identity: Vec<u8>,
    _phantom: PhantomData<T>,
}

impl<T: IdentityType, AE: AsyncExecutor> HealthState<T, AE> {
    fn new(settings: Arc<Settings<AE>>, identity: Vec<u8>) -> Self {
        Self {
            settings,
            smooth_rtt: None,
            rtt_variance: None,
            incremental_counter: 0,
            retry_count: 0,
            last_sent_time: 0,
            last_sent_next_in: 0,
            current_pn: 0,
            shadowride_pending: None,
            identity,
            _phantom: PhantomData,
        }
    }

    /// Get smooth RTT or default value.
    fn smooth_rtt_or_default(&self) -> f64 {
        self.smooth_rtt.unwrap_or(self.settings.get(&RTT_DEFAULT) as f64)
    }

    /// Compute the next packet number: (unix_timestamp_seconds << 32) | incremental.
    fn next_packet_number(&mut self) -> u64 {
        self.incremental_counter += 1;
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (self.incremental_counter as u64)
    }

    /// Compute a random next_in delay, clamped to configured bounds.
    fn compute_next_in(&self) -> u32 {
        let min = self.settings.get(&HEALTH_CHECK_NEXT_IN_MIN);
        let max = self.settings.get(&HEALTH_CHECK_NEXT_IN_MAX);
        get_rng().gen_range(min..=max) as u32
    }

    /// Compute timeout from RTT or use default, clamped to bounds.
    fn compute_timeout(&self) -> u64 {
        let timeout_min = self.settings.get(&TIMEOUT_MIN);
        let timeout_max = self.settings.get(&TIMEOUT_MAX);

        match (self.smooth_rtt, self.rtt_variance) {
            (Some(srtt), Some(rttvar)) => {
                let factor = self.settings.get(&TIMEOUT_RTT_FACTOR);
                ((srtt + rttvar) * factor) as u64
            }
            _ => self.settings.get(&TIMEOUT_DEFAULT),
        }
        .clamp(timeout_min, timeout_max)
    }

    /// Update RTT using EWMA algorithm.
    fn update_rtt(&mut self, receive_time: u128) {
        let packet_rtt = (receive_time as f64) - (self.last_sent_time as f64) - (self.last_sent_next_in as f64);
        let rtt_min = self.settings.get(&RTT_MIN) as f64;
        let rtt_max = self.settings.get(&RTT_MAX) as f64;
        let packet_rtt = packet_rtt.clamp(rtt_min, rtt_max);

        match self.smooth_rtt {
            None => {
                self.smooth_rtt = Some(packet_rtt);
                self.rtt_variance = Some(packet_rtt / 2.0);
            }
            Some(srtt) => {
                let alpha = self.settings.get(&RTT_ALPHA);
                let beta = self.settings.get(&RTT_BETA);
                let new_srtt = (1.0 - alpha) * srtt + alpha * packet_rtt;
                let new_rttvar = (1.0 - beta) * self.rtt_variance.unwrap() + beta * (new_srtt - packet_rtt).abs();
                self.smooth_rtt = Some(new_srtt.clamp(rtt_min, rtt_max));
                self.rtt_variance = Some(new_rttvar);
            }
        }

        debug!("RTT updated: smooth_rtt={:.1}ms, variance={:.1}ms", self.smooth_rtt.unwrap(), self.rtt_variance.unwrap());
    }

    /// Create a health check packet (empty body + tailor).
    fn create_health_check_packet(&self, pn: u64, next_in: u32) -> DynamicByteBuffer {
        let identity_buffer = self.settings.pool().allocate_precise_from_slice_with_capacity(&self.identity, 0, 0);
        let tailor = Tailor::health_check(T::from_bytes(identity_buffer.slice()), next_in, pn);
        let tailor_buffer = self.settings.pool().allocate(Some(T::length()));
        tailor.to_buffer(tailor_buffer)
    }
}

/// Health check provider for client-side decay cycle management.
pub struct HealthProvider<T: IdentityType + 'static, AE: AsyncExecutor + 'static, SM: SessionManager + 'static> {
    manager: Weak<SM>,
    state: Arc<RwLock<HealthState<T, AE>>>,
    response_tx: Sender<(u32, u128)>,
    shadowride_tx: Sender<()>,
}

impl<T: IdentityType, AE: AsyncExecutor, SM: SessionManager + Send + Sync> HealthProvider<T, AE, SM> {
    /// Create a new health provider with pre-created channel senders.
    pub fn new(
        manager: Weak<SM>,
        settings: Arc<Settings<AE>>,
        identity: Vec<u8>,
        response_tx: Sender<(u32, u128)>,
        shadowride_tx: Sender<()>,
    ) -> Self {
        let state = Arc::new(RwLock::new(HealthState::new(settings, identity)));
        Self {
            manager,
            state,
            response_tx,
            shadowride_tx,
        }
    }

    /// Start the background decay cycle timer.
    pub async fn start(&mut self, response_rx: Receiver<(u32, u128)>, shadowride_rx: Receiver<()>) {
        let manager = self.manager.clone();
        let state = self.state.clone();
        let executor = {
            let lock = state.read().await;
            lock.settings.executor().clone()
        };
        executor.spawn(Self::timer_task(manager, state, response_rx, shadowride_rx));
        debug!("HealthProvider: decay cycle started");
    }

    /// Called when a packet with HEALTH_CHECK flag is received.
    pub async fn feed_input(&self, tailor: &Tailor<T>) {
        let state = self.state.read().await;

        if tailor.packet_number != state.current_pn {
            debug!("HealthProvider: discarding health check with unexpected PN (got {}, expected {})", tailor.packet_number, state.current_pn);
            return;
        }

        let receive_time = unix_timestamp_ms();
        let server_next_in = tailor.time.clamp(
            state.settings.get(&HEALTH_CHECK_NEXT_IN_MIN) as u32,
            state.settings.get(&HEALTH_CHECK_NEXT_IN_MAX) as u32,
        );

        let _ = self.response_tx.send((server_next_in, receive_time)).await;
    }

    /// Called before a data packet is sent. May modify the tailor for shadowriding.
    pub async fn feed_output(&self, tailor: &mut Tailor<T>) {
        if tailor.flags.contains(PacketFlags::HEALTH_CHECK) {
            return;
        }

        let mut state = self.state.write().await;
        if let Some((pn, next_in)) = state.shadowride_pending.take() {
            tailor.flags |= PacketFlags::HEALTH_CHECK;
            tailor.time = next_in;
            tailor.packet_number = pn;
            state.last_sent_time = unix_timestamp_ms();
            debug!("HealthProvider: shadowride attached (PN={}, next_in={}ms)", pn, next_in);

            let _ = self.shadowride_tx.send(()).await;
        }
    }

    /// Background timer task implementing the client-side decay cycle.
    async fn timer_task(
        manager: Weak<SM>,
        state: Arc<RwLock<HealthState<T, AE>>>,
        mut response_rx: Receiver<(u32, u128)>,
        mut shadowride_rx: Receiver<()>,
    ) {
        let mut server_next_in: Option<u32> = None;

        loop {
            // Step 1: Prepare the next health check.
            let (pn, my_next_in) = {
                let mut st = state.write().await;
                let pn = st.next_packet_number();
                let my_next_in = st.compute_next_in();
                st.current_pn = pn;
                st.last_sent_next_in = my_next_in;
                (pn, my_next_in)
            };

            // Step 2: Wait server's previous next_in with shadowriding, or send immediately.
            if let Some(srv_ni) = server_next_in {
                let rtt = state.read().await.smooth_rtt_or_default();
                let pre_wait = ((srv_ni as f64) - rtt).max(0.0) as u64;
                sleep(Duration::from_millis(pre_wait)).await;

                // Enter shadowride window.
                {
                    let mut st = state.write().await;
                    st.shadowride_pending = Some((pn, my_next_in));
                }

                let shadowride_window = (rtt * 2.0).max(1.0) as u64;
                let mut pool = FuturePool::new();
                pool.add(async { sleep(Duration::from_millis(shadowride_window)).await; false });
                pool.add(async {
                    cfg_if::cfg_if! {
                        if #[cfg(feature = "tokio")] {
                            let _ = shadowride_rx.recv().await;
                        } else if #[cfg(feature = "async-std")] {
                            let _ = shadowride_rx.recv().await;
                        }
                    }
                    true
                });

                let shadowridden = pool.next().await.unwrap_or(false);
                drop(pool);

                if !shadowridden {
                    let mut st = state.write().await;
                    st.shadowride_pending = None;
                    st.last_sent_time = unix_timestamp_ms();
                    let packet = st.create_health_check_packet(pn, my_next_in);
                    drop(st);

                    let Some(mgr) = manager.upgrade() else {
                        debug!("HealthProvider: session manager dropped, stopping");
                        break;
                    };
                    if let Err(err) = mgr.send_packet(packet, true).await {
                        debug!("HealthProvider: failed to send health check: {:?}", err);
                    }
                }
            } else {
                let packet = {
                    let mut st = state.write().await;
                    st.last_sent_time = unix_timestamp_ms();
                    st.create_health_check_packet(pn, my_next_in)
                };

                let Some(mgr) = manager.upgrade() else {
                    debug!("HealthProvider: session manager dropped, stopping");
                    break;
                };
                if let Err(err) = mgr.send_packet(packet, true).await {
                    debug!("HealthProvider: failed to send health check: {:?}", err);
                }
            }

            // Step 3: Wait for response (my_next_in + timeout).
            let timeout_ms = {
                let st = state.read().await;
                (my_next_in as u64) + st.compute_timeout()
            };

            let mut pool = FuturePool::new();
            pool.add(async { sleep(Duration::from_millis(timeout_ms)).await; DecayEvent::Timeout });
            pool.add(async {
                cfg_if::cfg_if! {
                    if #[cfg(feature = "tokio")] {
                        match response_rx.recv().await {
                            Some((ni, time)) => DecayEvent::ResponseReceived { server_next_in: ni, receive_time: time },
                            None => DecayEvent::Timeout,
                        }
                    } else if #[cfg(feature = "async-std")] {
                        match response_rx.recv().await {
                            Ok((ni, time)) => DecayEvent::ResponseReceived { server_next_in: ni, receive_time: time },
                            Err(_) => DecayEvent::Timeout,
                        }
                    }
                }
            });

            match pool.next().await {
                Some(DecayEvent::ResponseReceived { server_next_in: srv_ni, receive_time }) => {
                    let mut st = state.write().await;
                    st.update_rtt(receive_time);
                    st.retry_count = 0;
                    server_next_in = Some(srv_ni);
                    debug!("HealthProvider: response received, server_next_in={}ms", srv_ni);
                }
                _ => {
                    let mut st = state.write().await;
                    st.retry_count += 1;
                    let max_retries = st.settings.get(&MAX_RETRIES);
                    if st.retry_count >= max_retries {
                        debug!("HealthProvider: connection decayed after {} retries", st.retry_count);
                        break;
                    }
                    debug!("HealthProvider: timeout, retry {}/{}", st.retry_count, max_retries);
                    server_next_in = None;
                }
            }

            drop(pool);
        }
    }
}
