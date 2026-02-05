//! Generic controller channel pattern.
//!
//! Provides a standardized communication pattern between a controller (internal)
//! and its handle (external). The pattern consists of three channel types:
//! - Command (C): Requests sent from handle to controller (broadcast - many handles, one controller)
//! - Return (R): Responses sent from controller to handle (broadcast - one controller, many handles)
//! - Output (O): Async events sent from controller to handle (broadcast - one controller, many handles)

use tokio::sync::broadcast;

/// Internal side of a controller channel pair.
///
/// Held by the controller's event loop. Receives commands and sends
/// return values and output events.
pub struct ControllerInternal<C: Clone, R: Clone, O: Clone> {
    api_tx: broadcast::Sender<C>,
    api_rx: broadcast::Receiver<C>,
    return_tx: broadcast::Sender<R>,
    /// Output sender - public for cloning to multiple loops.
    pub output_tx: broadcast::Sender<O>,
}

impl<C: Clone, R: Clone, O: Clone> ControllerInternal<C, R, O> {
    /// Receive the next command from the handle.
    pub async fn recv(&mut self) -> Option<C> {
        self.api_rx.recv().await.ok()
    }

    /// Send a return value (response to a command).
    /// All handles will receive this.
    pub fn ret(&self, value: R) -> bool {
        self.return_tx.send(value).is_ok()
    }

    /// Send an output event to all handles.
    pub fn send(&self, event: O) -> bool {
        self.output_tx.send(event).is_ok()
    }

    /// Clone the API sender for creating additional receivers.
    pub fn api_sender(&self) -> broadcast::Sender<C> {
        self.api_tx.clone()
    }

    /// Clone the API sender for creating additional receivers.
    pub fn api_receiver(&self) -> broadcast::Receiver<C> {
        self.api_tx.subscribe()
    }
}

/// Handle side of a controller channel pair.
///
/// Held by external code. Sends commands and receives return values
/// and output events. This handle is Clone - each clone gets its own
/// receivers for returns and outputs.
pub struct ControllerHandle<C: Clone, R: Clone, O: Clone> {
    api_tx: broadcast::Sender<C>,
    return_tx: broadcast::Sender<R>,
    return_rx: broadcast::Receiver<R>,
    output_tx: broadcast::Sender<O>,
    output_rx: broadcast::Receiver<O>,
}

impl<C: Clone, R: Clone, O: Clone> Clone for ControllerHandle<C, R, O> {
    fn clone(&self) -> Self {
        Self {
            api_tx: self.api_tx.clone(),
            return_tx: self.return_tx.clone(),
            return_rx: self.return_tx.subscribe(),
            output_tx: self.output_tx.clone(),
            output_rx: self.output_tx.subscribe(),
        }
    }
}

impl<C: Clone, R: Clone, O: Clone> ControllerHandle<C, R, O> {
    /// Send a command and wait for its return value.
    ///
    /// Returns `None` if the controller is shut down.
    pub async fn send(&mut self, cmd: C) -> Option<R> {
        self.api_tx.send(cmd).ok()?;
        self.return_rx.recv().await.ok()
    }

    /// Send a command without waiting for a return value.
    ///
    /// Use this for fire-and-forget commands.
    pub fn send_nowait(&self, cmd: C) -> bool {
        self.api_tx.send(cmd).is_ok()
    }

    /// Receive the next output event.
    ///
    /// Returns `None` if the controller is shut down.
    pub async fn recv(&mut self) -> Option<O> {
        self.output_rx.recv().await.ok()
    }

    /// Clone the API sender for sharing with other callers.
    pub fn api_sender(&self) -> broadcast::Sender<C> {
        self.api_tx.clone()
    }

    /// Clone the API sender for sharing with other callers.
    pub fn api_receiver(&self) -> broadcast::Receiver<C> {
        self.api_tx.subscribe()
    }
}

/// Create a new controller channel pair.
///
/// # Type Parameters
/// - `C`: Command type (requests from handle to controller) - must be Clone
/// - `R`: Return type (responses from controller to handle) - must be Clone
/// - `O`: Output type (async events from controller to handle) - must be Clone
pub fn new<C: Clone, R: Clone, O: Clone>(buffer: usize) -> (ControllerInternal<C, R, O>, ControllerHandle<C, R, O>) {
    let (api_tx, api_rx) = broadcast::channel(buffer);
    let (return_tx, return_rx) = broadcast::channel(buffer);
    let (output_tx, output_rx) = broadcast::channel(buffer);

    (
        ControllerInternal {
            api_tx: api_tx.clone(),
            api_rx: api_rx,
            return_tx: return_tx.clone(),
            output_tx: output_tx.clone(),
        },
        ControllerHandle {
            api_tx,
            return_tx,
            return_rx,
            output_tx,
            output_rx,
        },
    )
}
