#[cfg(all(test, feature = "tokio", feature = "server"))]
#[path = "../../tests/session/client_health.rs"]
mod tests;

/// Health check provider implementing the decay cycle for connection liveness tracking.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer, FixedByteBuffer};
use crate::cache::SharedValue;
use crate::crypto::{ClientCryptoTool, ClientData};
use crate::session::SessionControllerError;
use crate::session::common::SessionManager;
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::settings::keys::*;
use crate::tailor::{ClientConnectionHandler, IdentityType, PacketFlags, ReturnCode, Tailor};
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, FuturePool, Mutex, WatchReceiver, WatchSender, sleep};
use crate::utils::unix_timestamp_ms;

/// Response type for the health check channel: (server_next_in, receive_time, optional handshake body, optional server identity).
type HealthResponse<T> = (u32, u128, Option<DynamicByteBuffer>, Option<T>);

/// Events produced when waiting for a health check response.
enum DecaySleepEvent<T: IdentityType> {
    Timeout,
    Terminated,
    ResponseReceived {
        server_next_in: u32,
        receive_time: u128,
        handshake_body: Option<DynamicByteBuffer>,
        server_identity: Option<T>,
    },
}

/// Events produced during the shadowride window.
enum DecayShadowrideEvent {
    Timeout,
    Terminated,
    Shadowridden,
}

/// Outcome of attempting to send a packet.
enum SendOutcome {
    Sent,
    Retry,
    Stop,
}

/// Internal state shared between the timer task and feed methods.
pub(super) struct HealthState<T: IdentityType + Clone, AE: AsyncExecutor, CC: ClientConnectionHandler> {
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
    /// Client crypto tool for encryption and identity.
    crypto_tool: SharedValue<ClientCryptoTool<T>>,
    /// Ephemeral handshake state stored between send and receive.
    client_data: Option<ClientData>,
    /// Client-side initial data generator for handshake.
    initial_data_generator: CC,
    /// Watch receiver for health check responses.
    /// Consumed once by `perform_handshake()` (taken out via `Option::take`).
    response_rx: Option<WatchReceiver<HealthResponse<T>>>,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, CC: ClientConnectionHandler> HealthState<T, AE, CC> {
    fn new(settings: Arc<Settings<AE>>, crypto_tool: SharedValue<ClientCryptoTool<T>>, initial_data_generator: CC, response_rx: WatchReceiver<HealthResponse<T>>) -> Self {
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
            crypto_tool,
            client_data: None,
            initial_data_generator,
            response_rx: Some(response_rx),
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

    /// Increment retry count and return whether we are still under the limit.
    fn increment_retry(&mut self) -> bool {
        self.retry_count += 1;
        self.retry_count < self.settings.get(&MAX_RETRIES)
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

    /// Build identity value for tailor construction.
    async fn identity_value(&mut self) -> T {
        self.crypto_tool.get().await.identity()
    }

    /// Create a health check packet (empty body + tailor).
    async fn create_health_check_packet(&mut self, pn: u64, next_in: u32) -> DynamicByteBuffer {
        let identity = self.identity_value().await;
        let buf = self.settings.pool().allocate(Some(T::length()));
        Tailor::health_check(buf, &identity, next_in, pn).into_buffer()
    }

    /// Create a handshake packet with encryption: handshake_secret || tailor.
    /// Also advances the crypto tool to the initial key so callers need not do it separately.
    async fn create_handshake_packet(&mut self, pn: u64, next_in: u32) -> DynamicByteBuffer {
        let settings = self.settings.clone();
        let initial_data = self.initial_data_generator.initial_data();
        // Single get(): extract identity, create handshake, and derive the updated tool all at once.
        let crypto = self.crypto_tool.get().await;
        let identity = crypto.identity();
        let (client_data, handshake_secret, initial_key) = crypto.create_handshake(settings.pool(), initial_data.slice());
        let updated_tool = crypto.with_key(&initial_key);
        // crypto borrow ends here (NLL); safe to write other fields and call set().
        self.client_data = Some(client_data);
        self.crypto_tool.set(updated_tool).await;

        let tailor_buffer = settings.pool().allocate(Some(T::length() + TAILOR_LENGTH));
        let tailor = Tailor::handshake(tailor_buffer, &identity, 0, next_in, pn, handshake_secret.len() as u16);
        handshake_secret.append(tailor.buffer().slice())
    }

    /// Process the server handshake response and derive the session key.
    /// Returns (session_key, server_initial_data).
    async fn process_handshake_response(&mut self, handshake_body: DynamicByteBuffer) -> Option<(FixedByteBuffer<32>, DynamicByteBuffer)> {
        let client_data = self.client_data.take()?;
        match self.crypto_tool.get().await.process_handshake_response(client_data, handshake_body, self.settings.pool()) {
            Ok((session_key, server_initial_data)) => Some((session_key, server_initial_data)),
            Err(err) => {
                debug!("ClientHealthProvider: handshake response decryption failed: {}", err);
                None
            }
        }
    }
}

/// Wait for a health check response or timeout.
async fn wait_for_response<T: IdentityType + Clone>(timeout_ms: u64, response_rx: &mut WatchReceiver<HealthResponse<T>>) -> DecaySleepEvent<T> {
    let mut pool = FuturePool::new();
    pool.add(async {
        sleep(Duration::from_millis(timeout_ms)).await;
        DecaySleepEvent::Timeout
    });
    pool.add(async {
        match response_rx.recv().await {
            Some((ni, time, body, identity)) => DecaySleepEvent::ResponseReceived {
                server_next_in: ni,
                receive_time: time,
                handshake_body: body,
                server_identity: identity,
            },
            None => DecaySleepEvent::Terminated,
        }
    });
    pool.next().await.unwrap_or(DecaySleepEvent::Terminated)
}

/// Health check provider for client-side decay cycle management.
pub struct ClientHealthProvider<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, SM: SessionManager + Send + Sync + 'static, CC: ClientConnectionHandler + 'static> {
    manager: Weak<SM>,
    state: Arc<Mutex<HealthState<T, AE, CC>>>,
    settings: Arc<Settings<AE>>,
    response_tx: WatchSender<HealthResponse<T>>,
    shadowride_tx: WatchSender<()>,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, SM: SessionManager + Send + Sync, CC: ClientConnectionHandler + 'static> ClientHealthProvider<T, AE, SM, CC> {
    /// Create a new health provider with pre-created channel senders.
    pub fn new(manager: Weak<SM>, settings: Arc<Settings<AE>>, state_crypto: SharedValue<ClientCryptoTool<T>>, response_tx: WatchSender<HealthResponse<T>>, shadowride_tx: WatchSender<()>, response_rx: WatchReceiver<HealthResponse<T>>, initial_data_generator: CC) -> Self {
        let state = Arc::new(Mutex::new(HealthState::new(settings.clone(), state_crypto, initial_data_generator, response_rx)));
        Self {
            manager,
            state,
            settings,
            response_tx,
            shadowride_tx,
        }
    }

    /// Perform the handshake and start the background health check timer.
    /// Must be called exactly once, after the background receive loop is running.
    pub async fn perform_handshake(&self) {
        let mut response_rx = self.state.lock().await.response_rx.take()
            .expect("perform_handshake() must be called exactly once");
        let handshake_factor = self.settings.get(&HANDSHAKE_NEXT_IN_FACTOR);
        let initial_server_next_in = self.do_handshake(&mut response_rx, handshake_factor).await;

        let timer_response_rx = self.response_tx.subscribe();
        let timer_shadowride_rx = self.shadowride_tx.subscribe();
        let manager = self.manager.clone();
        let state = self.state.clone();
        let executor = self.settings.executor().clone();
        executor.spawn(Self::timer_task(manager, state, timer_response_rx, timer_shadowride_rx, initial_server_next_in));
        debug!("ClientHealthProvider: decay cycle started");
    }

    /// Called when a packet with HEALTH_CHECK flag is received.
    pub async fn feed_input(&self, tailor: Tailor<T>) -> Result<(), SessionControllerError> {
        let pn = tailor.packet_number();
        let time = tailor.time();

        let state = self.state.lock().await;

        if pn != state.current_pn {
            debug!("ClientHealthProvider: discarding health check with unexpected PN (got {}, expected {})", pn, state.current_pn);
            return Ok(());
        }

        let receive_time = unix_timestamp_ms();
        let server_next_in = time.clamp(state.settings.get(&HEALTH_CHECK_NEXT_IN_MIN) as u32, state.settings.get(&HEALTH_CHECK_NEXT_IN_MAX) as u32);

        drop(state);
        if self.response_tx.send((server_next_in, receive_time, None, None)) {
            Ok(())
        } else {
            Err(SessionControllerError::HealthProviderDied)
        }
    }

    /// Called when a packet with HANDSHAKE flag is received, carrying the server handshake body.
    pub async fn feed_handshake_input(&self, tailor: Tailor<T>, body: DynamicByteBuffer) -> Result<(), SessionControllerError> {
        let pn = tailor.packet_number();
        let time = tailor.time();

        let state = self.state.lock().await;

        if pn != state.current_pn {
            debug!("ClientHealthProvider: discarding handshake with unexpected PN (got {}, expected {})", pn, state.current_pn);
            return Ok(());
        }

        let receive_time = unix_timestamp_ms();
        let server_next_in = time.clamp(state.settings.get(&HEALTH_CHECK_NEXT_IN_MIN) as u32, state.settings.get(&HEALTH_CHECK_NEXT_IN_MAX) as u32);

        let server_identity = Some(tailor.identity());
        drop(state);
        if self.response_tx.send((server_next_in, receive_time, Some(body), server_identity)) {
            Ok(())
        } else {
            Err(SessionControllerError::HealthProviderDied)
        }
    }

    /// Called before a data packet is sent. May modify the tailor for shadowriding.
    pub async fn feed_output(&self, tailor: Tailor<T>) -> Result<(), SessionControllerError> {
        if tailor.flags().contains(PacketFlags::HEALTH_CHECK) {
            return Ok(());
        }

        let shadowridden = {
            let mut state = self.state.lock().await;
            if let Some((pn, next_in)) = state.shadowride_pending.take() {
                tailor.set_flags(tailor.flags() | PacketFlags::HEALTH_CHECK);
                tailor.set_time(next_in);
                tailor.set_packet_number_raw(pn);
                state.last_sent_time = unix_timestamp_ms();
                debug!("ClientHealthProvider: shadowride attached (PN={}, next_in={}ms)", pn, next_in);
                true
            } else {
                false
            }
        };

        if shadowridden {
            if !self.shadowride_tx.send(()) {
                return Err(SessionControllerError::HealthProviderDied);
            }
        }

        Ok(())
    }

    /// Send a packet via the session manager, incrementing retry on failure.
    async fn try_send(&self, packet: DynamicByteBuffer) -> SendOutcome {
        Self::try_send_static(&self.manager, packet, &self.state).await
    }

    /// Static version of try_send for use in spawned background tasks.
    async fn try_send_static(manager: &Weak<SM>, packet: DynamicByteBuffer, state: &Arc<Mutex<HealthState<T, AE, CC>>>) -> SendOutcome {
        let Some(mgr) = manager.upgrade() else {
            debug!("ClientHealthProvider: session manager dropped");
            return SendOutcome::Stop;
        };
        if let Err(err) = mgr.send_packet(packet, true).await {
            debug!("ClientHealthProvider: failed to send packet: {:?}", err);
            let mut st = state.lock().await;
            if st.increment_retry() {
                debug!("ClientHealthProvider: retry {}/{}", st.retry_count, st.settings.get(&MAX_RETRIES));
                return SendOutcome::Retry;
            }
            debug!("ClientHealthProvider: max retries reached after {}", st.retry_count);
            return SendOutcome::Stop;
        }
        SendOutcome::Sent
    }

    /// Perform the client handshake exchange with retry logic.
    async fn do_handshake(
        &self,
        response_rx: &mut WatchReceiver<HealthResponse<T>>,
        handshake_factor: f64,
    ) -> Option<u32> {
        loop {
            let (packet, next_in) = {
                let mut st = self.state.lock().await;
                let pn = st.next_packet_number();
                let next_in = st.compute_next_in();
                st.current_pn = pn;
                st.last_sent_time = unix_timestamp_ms();

                // create_handshake_packet now also advances crypto_tool to the initial key.
                let packet = st.create_handshake_packet(pn, next_in).await;
                (packet, next_in)
            };

            match self.try_send(packet).await {
                SendOutcome::Sent => debug!("do_handshake: handshake packet sent"),
                SendOutcome::Retry => { debug!("do_handshake: retry"); continue; },
                SendOutcome::Stop => { debug!("do_handshake: stop"); return None; },
            }

            let timeout_ms = {
                let st = self.state.lock().await;
                let handshake_delay = (next_in as f64 * handshake_factor) as u64;
                handshake_delay + st.compute_timeout()
            };
            debug!("do_handshake: waiting for response, timeout={}ms", timeout_ms);

            match wait_for_response(timeout_ms, response_rx).await {
                DecaySleepEvent::Timeout => {
                    debug!("do_handshake: TIMEOUT");
                    let mut st = self.state.lock().await;
                    if st.increment_retry() {
                        debug!("ClientHealthProvider: handshake timeout, retry {}/{}", st.retry_count, st.settings.get(&MAX_RETRIES));
                        continue;
                    }
                    debug!("ClientHealthProvider: handshake failed after {} retries", st.retry_count);
                    return None;
                }
                DecaySleepEvent::Terminated => {
                    debug!("ClientHealthProvider: channel closed during handshake");
                    return None;
                }
                DecaySleepEvent::ResponseReceived {
                    server_next_in,
                    handshake_body,
                    server_identity,
                    ..
                } => {
                    let mut st = self.state.lock().await;
                    st.retry_count = 0;

                    if let Some(body) = handshake_body {
                        match st.process_handshake_response(body).await {
                            Some((session_key, _server_initial_data)) => {
                                // Single get() shared by both branches.
                                let tool = st.crypto_tool.get().await;
                                let updated_tool = if let Some(new_identity) = server_identity {
                                    tool.with_key_and_identity(&session_key, new_identity)
                                } else {
                                    tool.with_key(&session_key)
                                };
                                st.crypto_tool.set(updated_tool).await;
                            }
                            None => return None,
                        }
                    }

                    debug!("ClientHealthProvider: handshake completed successfully");
                    return Some(server_next_in);
                }
            }
        }
    }

    /// Attempt to send a health check, with shadowriding if a previous server_next_in is available.
    async fn send_or_shadowride(manager: &Weak<SM>, state: &Arc<Mutex<HealthState<T, AE, CC>>>, shadowride_rx: &mut WatchReceiver<()>, server_next_in: Option<u32>, pn: u64, next_in: u32) -> SendOutcome {
        if let Some(srv_ni) = server_next_in {
            let rtt = state.lock().await.smooth_rtt_or_default();
            let pre_wait = ((srv_ni as f64) - rtt).max(0.0) as u64;
            sleep(Duration::from_millis(pre_wait)).await;

            {
                let mut st = state.lock().await;
                st.shadowride_pending = Some((pn, next_in));
            }

            let shadowride_window = (rtt * 2.0).max(1.0) as u64;
            let shadowridden = {
                let mut pool = FuturePool::new();
                pool.add(async {
                    sleep(Duration::from_millis(shadowride_window)).await;
                    DecayShadowrideEvent::Timeout
                });
                pool.add(async {
                    match shadowride_rx.recv().await {
                        Some(_) => DecayShadowrideEvent::Shadowridden,
                        None => DecayShadowrideEvent::Terminated,
                    }
                });
                pool.next().await.unwrap_or(DecayShadowrideEvent::Terminated)
            };

            match shadowridden {
                DecayShadowrideEvent::Timeout => {
                    let mut st = state.lock().await;
                    st.shadowride_pending = None;
                    st.last_sent_time = unix_timestamp_ms();
                    let packet = st.create_health_check_packet(pn, next_in).await;
                    drop(st);
                    Self::try_send_static(manager, packet, state).await
                }
                DecayShadowrideEvent::Terminated => {
                    debug!("ClientHealthProvider: shadowride channel closed, stopping");
                    SendOutcome::Stop
                }
                DecayShadowrideEvent::Shadowridden => {
                    debug!("ClientHealthProvider: health check shadowridden");
                    SendOutcome::Sent
                }
            }
        } else {
            let packet = {
                let mut st = state.lock().await;
                st.last_sent_time = unix_timestamp_ms();
                st.create_health_check_packet(pn, next_in).await
            };
            Self::try_send_static(manager, packet, state).await
        }
    }

    /// Background timer task implementing the client-side decay cycle.
    async fn timer_task(manager: Weak<SM>, state: Arc<Mutex<HealthState<T, AE, CC>>>, mut response_rx: WatchReceiver<HealthResponse<T>>, mut shadowride_rx: WatchReceiver<()>, initial_server_next_in: Option<u32>) {
        let mut server_next_in = initial_server_next_in;

        loop {
            let (pn, my_next_in) = {
                let mut st = state.lock().await;
                let pn = st.next_packet_number();
                let my_next_in = st.compute_next_in();
                st.current_pn = pn;
                st.last_sent_next_in = my_next_in;
                (pn, my_next_in)
            };

            match Self::send_or_shadowride(&manager, &state, &mut shadowride_rx, server_next_in, pn, my_next_in).await {
                SendOutcome::Sent => {}
                SendOutcome::Retry => {
                    server_next_in = None;
                    continue;
                }
                SendOutcome::Stop => break,
            }

            let timeout_ms = {
                let st = state.lock().await;
                (my_next_in as u64) + st.compute_timeout()
            };

            match wait_for_response(timeout_ms, &mut response_rx).await {
                DecaySleepEvent::Timeout => {
                    let mut st = state.lock().await;
                    if st.increment_retry() {
                        debug!("ClientHealthProvider: response timeout, retry {}/{}", st.retry_count, st.settings.get(&MAX_RETRIES));
                        server_next_in = None;
                        continue;
                    }
                    debug!("ClientHealthProvider: connection decayed after {} retries", st.retry_count);
                    break;
                }
                DecaySleepEvent::Terminated => {
                    debug!("ClientHealthProvider: response channel closed, stopping");
                    break;
                }
                DecaySleepEvent::ResponseReceived {
                    server_next_in: srv_ni,
                    receive_time,
                    ..
                } => {
                    let mut st = state.lock().await;
                    st.update_rtt(receive_time);
                    st.retry_count = 0;
                    server_next_in = Some(srv_ni);
                    debug!("ClientHealthProvider: response received, server_next_in={}ms", srv_ni);
                }
            }
        }
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, SM: SessionManager + Send + Sync, CC: ClientConnectionHandler> Drop for ClientHealthProvider<T, AE, SM, CC> {
    /// NB! There's no need for synchronization: even if a couple of packets slip through after termination, they will just get discarded.
    fn drop(&mut self) {
        let manager = self.manager.clone();
        let state = self.state.clone();
        let packet = self.settings.pool().allocate(Some(T::length()));

        self.settings.executor().spawn(async move {
            let identity = state.lock().await.crypto_tool.get().await.identity();
            let packet_number = ((unix_timestamp_ms() / 1000) as u64) << 32;
            let tailor = Tailor::termination(packet, &identity, ReturnCode::Success, packet_number);

            if let Some(mgr) = manager.upgrade() {
                match mgr.send_packet(tailor.into_buffer(), true).await {
                    Ok(()) => debug!("ClientHealthProvider: termination packet sent"),
                    Err(err) => debug!("ClientHealthProvider: failed to send termination packet: {err}"),
                }
            }
        });
    }
}
