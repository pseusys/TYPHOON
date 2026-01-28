use std::io::Error as IoError;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use cfg_if::cfg_if;
use thiserror::Error;

use crate::bytes::ByteBuffer;

cfg_if! {
    if #[cfg(feature = "tokio")] {
        use tokio::net::UdpSocket as TokioSocket;
    } else if #[cfg(feature = "async-std")] {
        use std::net::UdpSocket as StdUdpSocket;
        use async_io::Async;
    }
}

/// Socket wrapper error

#[derive(Error, Debug)]
#[error("asynchronous socket IO error: {}", source.to_string())]
pub struct SocketError {
    source: IoError,
}

impl SocketError {
    #[inline]
    fn new_socket_error(source: IoError) -> Self {
        SocketError {
            source,
        }
    }
}

/// Runtime-agnostic socket wrapper

pub struct Socket {
    #[cfg(feature = "tokio")]
    sock: TokioSocket,

    #[cfg(feature = "async-std")]
    sock: Async<StdUdpSocket>,
}

// TODO: consider using DO_REUSEPORT
impl Socket {
    #[cfg(feature = "tokio")]
    pub async fn new(peer: SocketAddr, local: Option<SocketAddr>) -> Result<Self, SocketError> {
        let local_addr = match local {
            Some(res) => res,
            None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
        };
        let sock = match TokioSocket::bind(local_addr).await {
            Ok(res) => res,
            Err(err) => return Err(SocketError::new_socket_error(err)),
        };
        if let Err(err) = sock.connect(peer).await {
            return Err(SocketError::new_socket_error(err));
        }
        Ok(Self {
            sock,
        })
    }

    #[cfg(feature = "async-std")]
    pub async fn new(peer: SocketAddr, local: Option<SocketAddr>) -> Result<Self, SocketError> {
        let local_addr = match local {
            Some(res) => res,
            None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
        };
        let sock = match StdUdpSocket::bind(local_addr) {
            Ok(res) => res,
            Err(err) => return Err(SocketError::new_socket_error(err)),
        };
        if let Err(err) = sock.connect(peer) {
            return Err(SocketError::new_socket_error(err));
        }
        match Async::new(sock) {
            Ok(res) => Ok(Self {
                sock: res,
            }),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    /// Send to socket

    #[cfg(feature = "tokio")]
    pub async fn send(&mut self, data: &ByteBuffer) -> Result<usize, SocketError> {
        match self.sock.send(data.slice()).await {
            Ok(res) => Ok(res),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    #[cfg(feature = "async-std")]
    pub async fn send(&mut self, data: &ByteBuffer) -> Result<usize, SocketError> {
        match self.sock.send(data.slice()).await {
            Ok(res) => Ok(res),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    /// Receive from socket

    #[cfg(feature = "tokio")]
    pub async fn recv(&mut self, buf: &ByteBuffer) -> Result<ByteBuffer, SocketError> {
        match self.sock.recv(buf.slice_mut()).await {
            Ok(res) => Ok(buf.rebuffer_end(res)),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    #[cfg(feature = "async-std")]
    pub async fn recv(&mut self, buf: &ByteBuffer) -> Result<ByteBuffer, SocketError> {
        match self.sock.recv(buf.slice_mut()).await {
            Ok(res) => Ok(buf.rebuffer_end(res)),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    /// Attempt best effort synchronous send a final message and close the socket

    #[cfg(feature = "tokio")]
    fn close(self, data: &ByteBuffer) -> Result<usize, SocketError> {
        match self.sock.try_send(data.slice()) {
            Ok(res) => Ok(res),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    #[cfg(feature = "async-std")]
    fn close(self, data: &ByteBuffer) -> Result<usize, SocketError> {
        match self.sock.into_inner() {
            Ok(inner_sock) => match inner_sock.send(data.slice()) {
                Ok(res) => Ok(res),
                Err(err) => Err(SocketError::new_socket_error(err)),
            },
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }
}
