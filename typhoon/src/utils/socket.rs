use std::io::Error as IoError;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use cfg_if::cfg_if;
use thiserror::Error;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};

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
        let local_addr = local.unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)));
        let sock = TokioSocket::bind(local_addr).await.map_err(SocketError::new_socket_error)?;
        if let Err(err) = sock.connect(peer).await {
            return Err(SocketError::new_socket_error(err));
        }
        Ok(Self {
            sock,
        })
    }

    #[cfg(feature = "async-std")]
    pub async fn new(peer: SocketAddr, local: Option<SocketAddr>) -> Result<Self, SocketError> {
        let local_addr = local.unwrap_or_else(||  SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)));
        let sock = StdUdpSocket::bind(local_addr).map_err(SocketError::new_socket_error)?;
        if let Err(err) = sock.connect(peer) {
            return Err(SocketError::new_socket_error(err));
        }
        Ok(Self {
            sock: Async::new(sock).map_err(SocketError::new_socket_error)?,
        })
    }

    /// Send to socket

    #[cfg(feature = "tokio")]
    pub async fn send(&self, data: DynamicByteBuffer) -> Result<usize, SocketError> {
        self.sock.send(data.slice()).await.map_err(SocketError::new_socket_error)
    }

    #[cfg(feature = "async-std")]
    pub async fn send(&self, data: DynamicByteBuffer) -> Result<usize, SocketError> {
        self.sock.send(data.slice()).await.map_err(SocketError::new_socket_error)
    }

    /// Receive from socket

    #[cfg(feature = "tokio")]
    pub async fn recv(&self, buf: DynamicByteBuffer) -> Result<DynamicByteBuffer, SocketError> {
        let res = self.sock.recv(buf.slice_mut()).await.map_err(SocketError::new_socket_error)?;
        Ok(buf.rebuffer_end(res))
    }

    #[cfg(feature = "async-std")]
    pub async fn recv(&self, buf: DynamicByteBuffer) -> Result<DynamicByteBuffer, SocketError> {
        let res = self.sock.recv(buf.slice_mut()).await.map_err(SocketError::new_socket_error)?;
        Ok(buf.rebuffer_end(res))
    }

    /// Attempt best effort synchronous send a final message and close the socket

    #[cfg(feature = "tokio")]
    fn close(self, data: DynamicByteBuffer) -> Result<usize, SocketError> {
        self.sock.try_send(data.slice()).map_err(SocketError::new_socket_error)
    }

    #[cfg(feature = "async-std")]
    fn close(self, data: DynamicByteBuffer) -> Result<usize, SocketError> {
        self.sock.into_inner().map_err(SocketError::new_socket_error)?.send(data.slice()).map_err(SocketError::new_socket_error)
    }
}
