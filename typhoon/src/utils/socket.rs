use std::io::Error as IoError;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use thiserror::Error;
use tokio::net::UdpSocket as TokioSocket;

use crate::bytes::ByteBuffer;

/// Socket wrapper error

#[derive(Error, Debug)]
#[error("asynchronous socket IO error: {}", source.to_string())]
pub struct SocketError {
    source: IoError,
}

impl SocketError {
    #[inline]
    fn new_socket_error(source: IoError) -> Self {
        SocketError { source }
    }
}

/// Socket wrapper using tokio UDP socket

pub struct Socket {
    sock: TokioSocket,
}

// TODO: consider using DO_REUSEPORT
impl Socket {
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
        Ok(Self { sock })
    }

    /// Send to socket
    pub async fn send(&self, data: ByteBuffer) -> Result<usize, SocketError> {
        match self.sock.send(data.slice()).await {
            Ok(res) => Ok(res),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    /// Receive from socket
    pub async fn recv(&self, buf: ByteBuffer) -> Result<ByteBuffer, SocketError> {
        match self.sock.recv(buf.slice_mut()).await {
            Ok(res) => Ok(buf.rebuffer_end(res)),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }

    /// Attempt best effort synchronous send a final message and close the socket
    fn close(self, data: ByteBuffer) -> Result<usize, SocketError> {
        match self.sock.try_send(data.slice()) {
            Ok(res) => Ok(res),
            Err(err) => Err(SocketError::new_socket_error(err)),
        }
    }
}
