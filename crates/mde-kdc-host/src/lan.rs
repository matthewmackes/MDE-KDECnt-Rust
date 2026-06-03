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

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use mde_kdc_proto::discovery::{Announce, DiscoveryRegistry};
use mde_kdc_proto::{codec, codec::FrameDecoder, wire::Packet};

use crate::discovery::UdpDiscovery;
use crate::error::HostError;
use crate::event::{EventSink, HostEvent};
use crate::pairing::PairingStore;
use crate::transport::{Connection, Transport};
use crate::PeerId;
use crate::{keygen, tls};

/// KDE Connect's stock TLS port. Both the UDP identity broadcast and the TCP+TLS
/// link use 1716; stock devices advertise 1716 by default, so `open` dials that on
/// the IP learned from the peer's UDP announce (announces carry identity, not the
/// wire port).
pub const KDC_TLS_PORT: u16 = 1716;

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

/// The LAN transport — the outbound half (host increment 3b.2d).
///
/// `start` spawns UDP discovery (folding peer announces into the shared registry
/// and emitting `PeerDiscovered`/`PeerLost` onto the event stream) and stashes the
/// sink. `open` resolves a paired peer's address from that registry, dials its TLS
/// port, completes the pinned-fingerprint handshake ([`tls::connect_pinned_tls`]),
/// and returns a framed [`LanConnection`]. The **inbound** TCP listener (accepting
/// peer-initiated links, which need the identity-first handshake to learn the peer
/// id) is the next increment; this transport handles the we-initiate direction.
pub struct LanTransport {
    announce: Announce,
    pairing: Arc<PairingStore>,
    registry: Arc<Mutex<DiscoveryRegistry>>,
    /// Taken (consumed) by `start`, which spawns its `run` loop.
    discovery: AsyncMutex<Option<UdpDiscovery>>,
    /// TCP port `open` dials on a discovered peer's IP. Defaults to [`KDC_TLS_PORT`];
    /// tests point it at a loopback server's ephemeral port.
    dial_port: u16,
    /// The event sink, captured in `start` so `open`'s `LanConnection` read loop can
    /// emit onto the same stream.
    sink: AsyncMutex<Option<EventSink>>,
    /// Fires on `shutdown` to stop the discovery loop; the join handle is awaited.
    shutdown_tx: AsyncMutex<Option<oneshot::Sender<()>>>,
    disc_task: AsyncMutex<Option<JoinHandle<()>>>,
}

impl LanTransport {
    /// Build the transport over a bound [`UdpDiscovery`] and the host pairing store.
    /// The discovery's shared registry is cloned so `open` can resolve addresses
    /// after `start` consumes the discovery into its `run` loop.
    #[must_use]
    pub fn new(announce: Announce, discovery: UdpDiscovery, pairing: Arc<PairingStore>) -> Self {
        let registry = discovery.shared_registry();
        Self {
            announce,
            pairing,
            registry,
            discovery: AsyncMutex::new(Some(discovery)),
            dial_port: KDC_TLS_PORT,
            sink: AsyncMutex::new(None),
            shutdown_tx: AsyncMutex::new(None),
            disc_task: AsyncMutex::new(None),
        }
    }

    /// Override the TCP port `open` dials (tests point it at a loopback server).
    #[must_use]
    pub fn with_dial_port(mut self, port: u16) -> Self {
        self.dial_port = port;
        self
    }

    /// The shared discovery registry handle (so a caller can inject peers in tests
    /// or read the address cache).
    #[must_use]
    pub fn registry(&self) -> Arc<Mutex<DiscoveryRegistry>> {
        Arc::clone(&self.registry)
    }
}

#[async_trait]
impl Transport for LanTransport {
    async fn start(&self, events: EventSink) -> Result<(), HostError> {
        let discovery = self
            .discovery
            .lock()
            .await
            .take()
            .ok_or_else(|| HostError::Transport("lan transport already started".into()))?;
        *self.sink.lock().await = Some(events.clone());
        let (stop_tx, stop_rx) = oneshot::channel();
        *self.shutdown_tx.lock().await = Some(stop_tx);
        *self.disc_task.lock().await = Some(tokio::spawn(discovery.run(events, stop_rx)));
        Ok(())
    }

    async fn open(&self, peer: &PeerId) -> Result<Box<dyn Connection>, HostError> {
        // Must be paired (we need the pinned fingerprint) and discovered (we need
        // an address to dial).
        let pin = {
            let device = self
                .pairing
                .get(peer.as_str())
                .ok_or_else(|| HostError::Transport("not_paired".into()))?;
            // An empty fingerprint = not yet pinned (first pair); accept any cert
            // and record it later. A pinned fingerprint must match.
            if device.fingerprint.is_empty() {
                None
            } else {
                Some(device.fingerprint.clone())
            }
        };
        let addr = UdpDiscovery::peer_addr_in(&self.registry, peer.as_str())
            .ok_or_else(|| HostError::Transport("not_discovered".into()))?;
        let dial = SocketAddr::new(addr.ip(), self.dial_port);
        let sink = self
            .sink
            .lock()
            .await
            .clone()
            .ok_or_else(|| HostError::Transport("lan transport not started".into()))?;
        let stream = tls::connect_pinned_tls(dial, peer.as_str(), pin)
            .await
            .map_err(|e| HostError::Transport(format!("connect: {e}")))?;
        let _ = sink.send(HostEvent::Connected(peer.clone()));
        Ok(Box::new(LanConnection::new(stream, peer.clone(), sink)))
    }

    fn local_announce(&self) -> &Announce {
        &self.announce
    }

    async fn shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.disc_task.lock().await.take() {
            let _ = task.await;
        }
        *self.sink.lock().await = None;
    }
}

/// Build this host's identity material (self-signed cert DER + its PKCS#8 key) from
/// the pairing store, for presenting on a TLS link. Exposed for the inbound
/// listener increment + tests.
pub fn host_identity(
    pairing: &PairingStore,
    device_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), HostError> {
    let pkcs8 = pairing.identity_pkcs8().to_vec();
    let cert = keygen::issue_identity_cert(&pkcs8, device_id)
        .map_err(|e| HostError::Transport(format!("identity cert: {e}")))?;
    Ok((cert, pkcs8))
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

    use crate::pairing::{DeviceRecord, PairingStore};
    use crate::transport::Transport;
    use crate::UdpDiscovery;
    use mde_kdc_proto::discovery::{Announce, DeviceType, DiscoveryRegistry};

    fn announce(id: &str) -> Announce {
        Announce {
            device_id: id.into(),
            device_name: format!("dev-{id}"),
            device_type: DeviceType::Desktop,
            protocol_version: 7,
            incoming_capabilities: vec![],
            outgoing_capabilities: vec![],
        }
    }

    #[tokio::test]
    async fn lan_transport_open_connects_to_a_discovered_paired_peer() {
        // End-to-end of the outbound path: a paired peer (pinned to a loopback TLS
        // server's fingerprint) is injected into discovery; `open` resolves its
        // address, completes the pinned handshake, and the returned connection's
        // `send` surfaces on the server's stream.
        let peer_pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let peer_cert = crate::keygen::issue_identity_cert(&peer_pkcs8, "phone-1").unwrap();
        let peer_fp = compute_fingerprint(&peer_cert);

        // The peer's TLS server on an ephemeral port; its read loop emits onto srv.
        let (srv_sink, mut srv_stream) = EventStream::channel();
        let server_addr = spawn_tls_server(peer_cert, peer_pkcs8, srv_sink).await;

        // Host pairing store: trust phone-1 with the server's pinned fingerprint.
        let tmp = tempfile::tempdir().unwrap();
        let mut store = PairingStore::open(tmp.path()).unwrap();
        store
            .pair(DeviceRecord {
                device_id: "phone-1".into(),
                device_name: "Phone".into(),
                paired_at_ms: 1,
                fingerprint: peer_fp,
            })
            .unwrap();
        let pairing = Arc::new(store);

        // Discovery on an ephemeral UDP port; dial the loopback server's port.
        let discovery = UdpDiscovery::bind("127.0.0.1:0".parse().unwrap(), announce("self"))
            .await
            .unwrap();
        let transport = LanTransport::new(announce("self"), discovery, pairing)
            .with_dial_port(server_addr.port());

        // Inject phone-1 into the registry at the loopback IP so `open` resolves it.
        {
            let reg: Arc<Mutex<DiscoveryRegistry>> = transport.registry();
            reg.lock()
                .unwrap()
                .inject_real_with_addr(announce("phone-1"), 1, server_addr);
        }

        // Start (captures the sink, spawns discovery) then open.
        let (host_sink, mut host_stream) = EventStream::channel();
        transport.start(host_sink).await.unwrap();
        let conn = transport
            .open(&PeerId::from("phone-1"))
            .await
            .expect("open should connect to the discovered, paired peer");
        assert_eq!(conn.peer().as_str(), "phone-1");

        // `open` emits Connected on the host stream.
        let connected = tokio::time::timeout(std::time::Duration::from_secs(2), host_stream.recv())
            .await
            .expect("connected before timeout");
        assert!(matches!(connected, Some(HostEvent::Connected(p)) if p.as_str() == "phone-1"));

        // A ping sent over the connection surfaces on the peer server's stream.
        conn.send(plugins::ping_packet(42, "hi".into()))
            .await
            .unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), srv_stream.recv())
            .await
            .expect("peer should receive the ping before timeout");
        assert!(matches!(got, Some(HostEvent::Packet { packet, .. }) if packet.id == 42));

        transport.shutdown().await;
    }

    #[tokio::test]
    async fn lan_transport_open_errors_when_peer_unpaired_or_undiscovered() {
        let tmp = tempfile::tempdir().unwrap();
        let pairing = Arc::new(PairingStore::open(tmp.path()).unwrap());
        let discovery = UdpDiscovery::bind("127.0.0.1:0".parse().unwrap(), announce("self"))
            .await
            .unwrap();
        let transport = LanTransport::new(announce("self"), discovery, pairing);
        let (sink, _stream) = EventStream::channel();
        transport.start(sink).await.unwrap();
        // Unknown peer → not_paired.
        let r = transport.open(&PeerId::from("nobody")).await;
        assert!(matches!(r, Err(HostError::Transport(ref m)) if m.contains("not_paired")));
        transport.shutdown().await;
    }
}
