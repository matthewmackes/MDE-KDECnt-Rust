//! The LAN transport's live peer link (host increment 3b.2c).
//!
//! [`LanConnection`] is the framed duplex link over a TLS stream — the reusable
//! core both the outbound `open` path and the inbound listener (next increment)
//! wrap around. On construction it splits the TLS stream: a spawned read loop
//! decodes `mde-kdc-proto` frames off the wire and emits each as a
//! [`HostEvent::Packet`] onto the shared event stream, while the write half is
//! parked behind an async mutex so [`Connection::send`] can frame + write packets
//! from any task. EOF / read error ends the loop with a [`HostEvent::Disconnected`].
//!
//! It's generic over the stream type so both `tokio_rustls::client::TlsStream` and
//! `tokio_rustls::server::TlsStream` (different concrete types) reuse it; each call
//! site monomorphizes and coerces to `Box<dyn Connection>`.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;

use mde_kdc_proto::{codec, codec::FrameDecoder, wire::Packet};

use crate::error::HostError;
use crate::event::{EventSink, HostEvent};
use crate::transport::Connection;
use crate::PeerId;

/// Inbound read-buffer chunk size. Frames are reassembled by the decoder, so this
/// only bounds a single `read` syscall, not a frame.
const READ_CHUNK_BYTES: usize = 8 * 1024;

/// A live TLS peer link: a spawned read loop drains inbound frames onto the event
/// stream; `send` frames + writes through the mutex-guarded write half.
pub struct LanConnection<S> {
    peer: PeerId,
    sink: EventSink,
    write: Arc<AsyncMutex<WriteHalf<S>>>,
}

impl<S> LanConnection<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Wrap an established TLS `stream` to `peer`. Splits the stream, spawns the
    /// read loop (emitting `Packet` events onto `sink`), and keeps the write half
    /// for [`Connection::send`].
    pub fn new(stream: S, peer: PeerId, sink: EventSink) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        tokio::spawn(read_loop(read_half, peer.clone(), sink.clone()));
        Self {
            peer,
            sink,
            write: Arc::new(AsyncMutex::new(write_half)),
        }
    }
}

/// Drain inbound frames off `read_half` and emit each decoded packet onto `sink`.
/// Stops on EOF (peer closed), a read error, or a malformed frame (which can't be
/// resynced), emitting `Disconnected` as it exits.
async fn read_loop<R>(mut read_half: R, peer: PeerId, sink: EventSink)
where
    R: AsyncRead + Unpin,
{
    let mut decoder = FrameDecoder::new();
    let mut buf = [0u8; READ_CHUNK_BYTES];
    loop {
        let n = match read_half.read(&mut buf).await {
            Ok(0) => break,  // clean EOF
            Ok(n) => n,      //
            Err(_) => break, // socket/TLS read error
        };
        decoder.feed(&buf[..n]);
        loop {
            match decoder.next_frame() {
                Ok(Some(packet)) => {
                    let _ = sink.send(HostEvent::Packet {
                        peer: peer.clone(),
                        packet,
                    });
                }
                Ok(None) => break, // need more bytes
                Err(e) => {
                    // A malformed frame can't be resynced on a stream protocol;
                    // surface it and tear the connection down.
                    let _ = sink.send(HostEvent::TransportError(format!("frame decode: {e}")));
                    let _ = sink.send(HostEvent::Disconnected(peer.clone()));
                    return;
                }
            }
        }
    }
    let _ = sink.send(HostEvent::Disconnected(peer.clone()));
}

#[async_trait]
impl<S> Connection for LanConnection<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn peer(&self) -> &PeerId {
        &self.peer
    }

    async fn send(&self, packet: Packet) -> Result<(), HostError> {
        let frame = codec::encode_frame(&packet)
            .map_err(|e| HostError::Transport(format!("encode: {e}")))?;
        let mut write = self.write.lock().await;
        write
            .write_all(frame.as_bytes())
            .await
            .map_err(|e| HostError::Transport(format!("write: {e}")))?;
        write
            .flush()
            .await
            .map_err(|e| HostError::Transport(format!("flush: {e}")))?;
        Ok(())
    }

    async fn close(&self) {
        // Shut down the write half; the peer's read loop then EOFs and the read
        // loops emit `Disconnected`. Best-effort — a half-open peer may already
        // be gone. We don't emit `Disconnected` here to keep the stream-end the
        // single source of that event.
        let _ = self.write.lock().await.shutdown().await;
        let _ = &self.sink; // sink retained for symmetry with the loopback link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventStream;
    use crate::tls::{build_server_config, compute_fingerprint, connect_pinned_tls};
    use mde_kdc_proto::plugins;
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};

    /// Spin a one-shot TLS server presenting `cert`/`pkcs8`, accept one client, and
    /// hand the accepted server-side `LanConnection` to `sink`. Returns its addr.
    async fn spawn_tls_server(cert: Vec<u8>, pkcs8: Vec<u8>, sink: EventSink) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let config = build_server_config(&cert, &pkcs8).expect("server config");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let tls = acceptor.accept(tcp).await.expect("server tls accept");
            // Keep the server connection alive for the test's lifetime.
            let conn = LanConnection::new(tls, PeerId::from("client"), sink);
            // Park so the read loop's task isn't dropped with the connection.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            drop(conn);
        });
        addr
    }

    #[tokio::test]
    async fn round_trips_a_ping_frame_over_real_tls() {
        // A real TLS handshake (pinned fingerprint) + a framed ping: the client's
        // `send` must surface as a `Packet` event on the server's stream.
        let pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let cert = crate::keygen::issue_identity_cert(&pkcs8, "server").unwrap();
        let fingerprint = compute_fingerprint(&cert);

        let (server_sink, mut server_stream) = EventStream::channel();
        let addr = spawn_tls_server(cert, pkcs8, server_sink).await;

        // Client connects, pinning the server's fingerprint, and wraps the stream.
        let client_tls = connect_pinned_tls(addr, "server", Some(fingerprint))
            .await
            .expect("client tls connect");
        let (client_sink, _client_stream) = EventStream::channel();
        let client_conn = LanConnection::new(client_tls, PeerId::from("server"), client_sink);

        // Send a ping; it should arrive on the server's event stream as a Packet.
        let ping = plugins::ping_packet(777, "hello".into());
        client_conn.send(ping.clone()).await.expect("send ping");

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), server_stream.recv())
            .await
            .expect("a packet should arrive before timeout");
        match got {
            Some(HostEvent::Packet { peer, packet }) => {
                assert_eq!(peer.as_str(), "client");
                assert_eq!(packet.id, 777);
                assert_eq!(packet.kind, ping.kind);
            }
            other => panic!("expected Packet, got {other:?}"),
        }
        client_conn.close().await;
    }

    #[tokio::test]
    async fn read_loop_emits_disconnected_on_eof() {
        // A plain TCP pair (no TLS needed to exercise the read loop's EOF edge):
        // wrap the server end, drop the client end, expect Disconnected.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let (sink, mut stream) = EventStream::channel();
        let _conn = LanConnection::new(server, PeerId::from("peer"), sink);
        drop(client); // client closes → server read loop EOFs

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv())
            .await
            .expect("disconnected before timeout");
        assert!(matches!(got, Some(HostEvent::Disconnected(p)) if p.as_str() == "peer"));
    }
}
