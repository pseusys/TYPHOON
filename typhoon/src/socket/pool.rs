//! Multiplexed server entrypoint: [`ClientPool`] owns every accepted [`ClientHandle`], keyed by
//! identity, and exposes a single `receive`/`send` pair instead of one handle per connection.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use crate::bytes::DynamicByteBuffer;
use crate::socket::client_handle::ClientHandle;
use crate::socket::error::ServerSocketError;
use crate::socket::server::Listener;
use crate::tailer::{IdentityType, ServerConnectionHandler};
use crate::utils::sync::{AsyncExecutor, Mutex, NotifyQueueReceiver, NotifyQueueSender, RwLock, create_notify_queue};

/// Server entrypoint that owns every connected client's [`ClientHandle`], keyed by identity.
/// Wraps a [`Listener`]: connection lifecycle, accept loop, and per-client receive pumps are all
/// handled internally — callers only see a multiplexed `receive`/`send` pair plus `disconnect`.
pub struct ClientPool<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> {
    listener: Arc<Listener<T, AE, IG>>,
    clients: RwLock<HashMap<T, Arc<ClientHandle<T, AE>>>>,
    incoming_tx: NotifyQueueSender<(T, DynamicByteBuffer)>,
    incoming_rx: Mutex<NotifyQueueReceiver<(T, DynamicByteBuffer)>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> ClientPool<T, AE, IG> {
    /// Wrap an already-built `Listener`. Call `start()` to begin accepting connections.
    pub fn new(listener: Listener<T, AE, IG>) -> Self {
        let (incoming_tx, incoming_rx) = create_notify_queue();
        Self {
            listener: Arc::new(listener),
            clients: RwLock::new(HashMap::new()),
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
        }
    }

    /// Start the underlying listener and the accept-pump task. Returns once both are running — it does not block for the pool's lifetime.
    pub async fn start(self: &Arc<Self>) {
        self.listener.start().await;
        let pool = Arc::clone(self);
        self.listener.settings().executor().spawn(async move {
            while let Ok(handle) = pool.listener.accept().await {
                pool.register(handle).await;
            }
        });
    }

    /// Register a newly-accepted handle: store it under its identity and spawn its receive pump.
    /// Silently overwrites any stale entry left by a same-identity re-handshake — the stale handle's own pump task notices the displacement (`receive()` errors) and leaves the map alone once it sees it no longer owns the slot.
    async fn register(self: &Arc<Self>, handle: ClientHandle<T, AE>) {
        let id = handle.identity().clone();
        let handle = Arc::new(handle);
        self.clients.write().await.insert(id.clone(), Arc::clone(&handle));
        let pool = Arc::clone(self);
        self.listener.settings().executor().spawn(async move {
            pool.pump(id, handle).await;
        });
    }

    /// Forward packets from one client into the shared queue until its connection ends, then remove it from the map — but only if no newer connection has already taken its place.
    async fn pump(self: Arc<Self>, id: T, handle: Arc<ClientHandle<T, AE>>) {
        while let Ok(buf) = handle.receive().await {
            self.incoming_tx.push((id.clone(), buf));
        }
        let mut clients = self.clients.write().await;
        if clients.get(&id).is_some_and(|current| Arc::ptr_eq(current, &handle)) {
            clients.remove(&id);
        }
    }

    /// Receive the next packet from any client, tagged with its identity. Call in a loop.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::ChannelClosed`] if the pool has stopped dispatching.
    pub async fn receive(&self) -> Result<(T, DynamicByteBuffer), ServerSocketError> {
        self.incoming_rx.lock().await.recv().await.ok_or(ServerSocketError::ChannelClosed)
    }

    /// Send a packet to the client identified by `identity`.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::UnknownClient`] if no client with that identity is currently
    /// connected, or whatever error the underlying [`ClientHandle::send`] reports.
    pub async fn send(&self, identity: &T, packet: DynamicByteBuffer) -> Result<(), ServerSocketError> {
        let handle = { self.clients.read().await.get(identity).cloned() };
        match handle {
            Some(handle) => handle.send(packet).await,
            None => Err(ServerSocketError::UnknownClient),
        }
    }

    /// Proactively end one client's connection.
    /// Sends a TERMINATION packet and removes the session; the corresponding pump task notices and removes the pool's own bookkeeping.
    pub async fn disconnect(&self, identity: &T) {
        let handle = { self.clients.read().await.get(identity).cloned() };
        if let Some(handle) = handle {
            handle.terminate().await;
        }
    }

    /// Identities of all clients currently connected through this pool.
    pub async fn connected_ids(&self) -> Vec<T> {
        self.clients.read().await.keys().cloned().collect()
    }
}
