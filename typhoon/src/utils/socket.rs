use std::io::Error as IoError;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(feature = "server")]
use std::net::UdpSocket as StdUdpSocket;

use cfg_if::cfg_if;
#[cfg(feature = "server")]
use log::{debug, trace};
use thiserror::Error;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};

cfg_if! {
    if #[cfg(feature = "tokio")] {
        use tokio::net::UdpSocket as TokioSocket;
    } else if #[cfg(feature = "async-std")] {
        use async_io::Async;
    }
}

#[cfg(all(target_os = "linux", feature = "server"))]
use std::io::ErrorKind;

#[cfg(all(target_os = "linux", feature = "server"))]
use socket2::{Domain, Protocol, Socket as S2Socket, Type};

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
        let local_addr = local.unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)));
        let sock = StdUdpSocket::bind(local_addr).map_err(SocketError::new_socket_error)?;
        if let Err(err) = sock.connect(peer) {
            return Err(SocketError::new_socket_error(err));
        }
        Ok(Self {
            sock: Async::new(sock).map_err(SocketError::new_socket_error)?,
        })
    }

    /// Bind a socket without connecting (for server use with multiple peers).
    #[cfg(all(feature = "tokio", feature = "server"))]
    pub async fn bind(local: SocketAddr) -> Result<Self, SocketError> {
        let sock = TokioSocket::bind(local).await.map_err(SocketError::new_socket_error)?;
        Ok(Self {
            sock,
        })
    }

    /// Bind a socket without connecting (for server use with multiple peers).
    #[cfg(all(feature = "async-std", feature = "server"))]
    pub async fn bind(local: SocketAddr) -> Result<Self, SocketError> {
        let sock = StdUdpSocket::bind(local).map_err(SocketError::new_socket_error)?;
        Ok(Self {
            sock: Async::new(sock).map_err(SocketError::new_socket_error)?,
        })
    }

    /// Bind `count` sockets to the same address using `SO_REUSEPORT`.
    /// The kernel distributes incoming datagrams across all sockets by 4-tuple hash,
    /// enabling N concurrent `recv_from` calls with no locking.
    /// `local.port()` must be > 0.
    #[cfg(all(target_os = "linux", feature = "server", feature = "tokio"))]
    pub fn bind_reuse_port(local: SocketAddr, count: usize) -> Result<Vec<Self>, SocketError> {
        if local.port() == 0 {
            return Err(SocketError::new_socket_error(IoError::new(ErrorKind::InvalidInput, "SO_REUSEPORT requires port > 0")));
        }

        let domain = if local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let s2 = S2Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(SocketError::new_socket_error)?;
            s2.set_reuse_port(true).map_err(SocketError::new_socket_error)?;
            s2.bind(&local.into()).map_err(SocketError::new_socket_error)?;
            s2.set_nonblocking(true).map_err(SocketError::new_socket_error)?;
            let std_sock: StdUdpSocket = s2.into();
            let tok_sock = TokioSocket::from_std(std_sock).map_err(SocketError::new_socket_error)?;
            sockets.push(Socket {
                sock: tok_sock,
            });
        }
        Ok(sockets)
    }

    /// Bind `count` sockets to the same address using `SO_REUSEPORT`.
    /// The kernel distributes incoming datagrams across all sockets by 4-tuple hash,
    /// enabling N concurrent `recv_from` calls with no locking.
    /// `local.port()` must be > 0.
    #[cfg(all(target_os = "linux", feature = "server", feature = "async-std"))]
    pub fn bind_reuse_port(local: SocketAddr, count: usize) -> Result<Vec<Self>, SocketError> {
        if local.port() == 0 {
            return Err(SocketError::new_socket_error(IoError::new(ErrorKind::InvalidInput, "SO_REUSEPORT requires port > 0")));
        }

        let domain = if local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let s2 = S2Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(SocketError::new_socket_error)?;
            s2.set_reuse_port(true).map_err(SocketError::new_socket_error)?;
            s2.bind(&local.into()).map_err(SocketError::new_socket_error)?;
            let std_sock: StdUdpSocket = s2.into();
            sockets.push(Socket {
                sock: Async::new(std_sock).map_err(SocketError::new_socket_error)?,
            });
        }
        Ok(sockets)
    }

    // Send to socket

    #[cfg(feature = "tokio")]
    pub async fn send(&self, data: DynamicByteBuffer) -> Result<usize, SocketError> {
        self.sock.send(data.slice()).await.map_err(SocketError::new_socket_error)
    }

    #[cfg(feature = "async-std")]
    pub async fn send(&self, data: DynamicByteBuffer) -> Result<usize, SocketError> {
        self.sock.send(data.slice()).await.map_err(SocketError::new_socket_error)
    }

    // Receive from socket

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

    // Send to a specific address (for unconnected sockets).

    #[cfg(all(feature = "tokio", feature = "server"))]
    pub async fn send_to(&self, data: DynamicByteBuffer, target: SocketAddr) -> Result<usize, SocketError> {
        let len = data.slice().len();
        match self.sock.send_to(data.slice(), target).await {
            Ok(sent) => {
                if sent < len {
                    debug!("socket: send_to partial write: {} of {} bytes sent to {}", sent, len, target);
                }
                trace!("socket: send_to {} bytes to {} → ok ({} sent)", len, target, sent);
                Ok(sent)
            }
            Err(e) => {
                debug!("socket: send_to {} bytes to {} → error: {}", len, target, e);
                Err(SocketError::new_socket_error(e))
            }
        }
    }

    #[cfg(all(feature = "async-std", feature = "server"))]
    pub async fn send_to(&self, data: DynamicByteBuffer, target: SocketAddr) -> Result<usize, SocketError> {
        let len = data.slice().len();
        match self.sock.send_to(data.slice(), target).await {
            Ok(sent) => {
                if sent < len {
                    debug!("socket: send_to partial write: {} of {} bytes sent to {}", sent, len, target);
                }
                trace!("socket: send_to {} bytes to {} → ok ({} sent)", len, target, sent);
                Ok(sent)
            }
            Err(e) => {
                debug!("socket: send_to {} bytes to {} → error: {}", len, target, e);
                Err(SocketError::new_socket_error(e))
            }
        }
    }

    // Receive from any peer, returning the data and source address.

    #[cfg(all(feature = "tokio", feature = "server"))]
    pub async fn recv_from(&self, buf: DynamicByteBuffer) -> Result<(DynamicByteBuffer, SocketAddr), SocketError> {
        match self.sock.recv_from(buf.slice_mut()).await {
            Ok((res, addr)) => {
                trace!("socket: recv_from {} bytes from {}", res, addr);
                Ok((buf.rebuffer_end(res), addr))
            }
            Err(e) => {
                debug!("socket: recv_from error: {}", e);
                Err(SocketError::new_socket_error(e))
            }
        }
    }

    #[cfg(all(feature = "async-std", feature = "server"))]
    pub async fn recv_from(&self, buf: DynamicByteBuffer) -> Result<(DynamicByteBuffer, SocketAddr), SocketError> {
        match self.sock.recv_from(buf.slice_mut()).await {
            Ok((res, addr)) => {
                trace!("socket: recv_from {} bytes from {}", res, addr);
                Ok((buf.rebuffer_end(res), addr))
            }
            Err(e) => {
                debug!("socket: recv_from error: {}", e);
                Err(SocketError::new_socket_error(e))
            }
        }
    }
}
