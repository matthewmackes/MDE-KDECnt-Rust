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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

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
        Self::new_seeded(stream, FrameDecoder::new(), peer, sink)
    }

    /// Like [`new`](Self::new), but continue an in-progress decode with a pre-seeded
    /// `decoder`. The inbound listener reads the identity frame first; any bytes it
    /// over-reads past that frame's newline live in the decoder's buffer and must carry
    /// into this read loop rather than being dropped on the floor.
    pub fn new_seeded(stream: S, decoder: FrameDecoder, peer: PeerId, sink: EventSink) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        tokio::spawn(read_loop(read_half, decoder, peer.clone(), sink.clone()));
        Self {
            peer,
            sink,
            write: Arc::new(AsyncMutex::new(write_half)),
        }
    }
}

/// Drain inbound frames off `read_half` and emit each decoded packet onto `sink`,
/// starting from any frames already buffered in the seeded `decoder` (the inbound path's
/// identity-frame residual). Stops on EOF (peer closed), a read error, or a malformed
/// frame (which can't be resynced), emitting `Disconnected` as it exits.
async fn read_loop<R>(mut read_half: R, mut decoder: FrameDecoder, peer: PeerId, sink: EventSink)
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; READ_CHUNK_BYTES];
    loop {
        // Drain every complete frame already buffered — the seeded residual on the first
        // pass, then whatever the previous read landed — before blocking on the next read.
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
        let n = match read_half.read(&mut buf).await {
            Ok(0) => break,  // clean EOF
            Ok(n) => n,      //
            Err(_) => break, // socket/TLS read error
        };
        decoder.feed(&buf[..n]);
    }
    let _ = sink.send(HostEvent::Disconnected(peer.clone()));
}

/// Read frames off `stream` until the first complete one. Returns the decoded packet plus
/// the [`FrameDecoder`] — which may hold bytes read *past* that frame's newline; the caller
/// must hand the decoder to the connection's read loop ([`LanConnection::new_seeded`]) so
/// those bytes aren't lost. Used by the inbound listener's identity-first handshake.
async fn read_first_frame<S>(stream: &mut S) -> Result<(Packet, FrameDecoder), HostError>
where
    S: AsyncRead + Unpin,
{
    let mut decoder = FrameDecoder::new();
    let mut buf = [0u8; READ_CHUNK_BYTES];
    loop {
        match decoder.next_frame() {
            Ok(Some(packet)) => return Ok((packet, decoder)),
            Ok(None) => {}
            Err(e) => return Err(HostError::Transport(format!("decode: {e}"))),
        }
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| HostError::Transport(format!("read: {e}")))?;
        if n == 0 {
            return Err(HostError::Transport("identity_eof".into()));
        }
        decoder.feed(&buf[..n]);
    }
}

/// Extract the [`Announce`] from a peer's first inbound frame, which must be a
/// `kdeconnect.identity` packet (mirrors [`mde_kdc_proto::discovery::decode_announce_datagram`]
/// but over the TCP framing). Any other packet kind is rejected.
fn announce_from_identity(packet: Packet) -> Result<Announce, HostError> {
    if packet.kind != "kdeconnect.identity" {
        return Err(HostError::Transport(format!(
            "expected_identity_got_{}",
            packet.kind
        )));
    }
    serde_json::from_value(packet.body)
        .map_err(|e| HostError::Transport(format!("identity_body: {e}")))
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
    /// If set, `start` binds a TCP listener here and accepts inbound peer-initiated links
    /// (mutual TLS + identity-first handshake). `None` = outbound-only (no listener).
    /// Production binds `0.0.0.0:`[`KDC_TLS_PORT`]; tests use `127.0.0.1:0`.
    listen_addr: Option<SocketAddr>,
    /// The actually-bound listener address (ephemeral port resolved), set by `start`.
    bound_addr: AsyncMutex<Option<SocketAddr>>,
    /// Accepted inbound connections keyed by peer id, kept alive so their write half
    /// survives for [`send_to`](Self::send_to) and their read loop keeps surfacing
    /// packets. One link per peer — a reconnect replaces (and drops) the prior.
    inbound: Arc<AsyncMutex<HashMap<String, Box<dyn Connection>>>>,
    /// Fires on `shutdown` to stop the accept loop; its join handle is awaited.
    listen_shutdown: AsyncMutex<Option<oneshot::Sender<()>>>,
    listen_task: AsyncMutex<Option<JoinHandle<()>>>,
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
            listen_addr: None,
            bound_addr: AsyncMutex::new(None),
            inbound: Arc::new(AsyncMutex::new(HashMap::new())),
            listen_shutdown: AsyncMutex::new(None),
            listen_task: AsyncMutex::new(None),
        }
    }

    /// Override the TCP port `open` dials (tests point it at a loopback server).
    #[must_use]
    pub fn with_dial_port(mut self, port: u16) -> Self {
        self.dial_port = port;
        self
    }

    /// Enable the **inbound listener**: `start` binds `addr` and accepts peer-initiated
    /// links. Production binds `0.0.0.0:`[`KDC_TLS_PORT`]; tests pass `127.0.0.1:0` and
    /// read the resolved port back via [`local_listen_addr`](Self::local_listen_addr).
    /// Without this, the transport is outbound-only.
    #[must_use]
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }

    /// The address the inbound listener actually bound (with the ephemeral port resolved),
    /// or `None` if listening is disabled or `start` hasn't run / has shut down.
    pub async fn local_listen_addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.lock().await
    }

    /// Send `packet` to a peer over its **inbound** (peer-initiated) connection. Errors
    /// with `no_inbound_connection` if the peer only ever connected outbound (whose
    /// `Connection` the caller holds directly from `open`) or isn't connected at all.
    pub async fn send_to(&self, peer: &PeerId, packet: Packet) -> Result<(), HostError> {
        let map = self.inbound.lock().await;
        match map.get(peer.as_str()) {
            Some(conn) => conn.send(packet).await,
            None => Err(HostError::Transport("no_inbound_connection".into())),
        }
    }

    /// The peers with a live inbound connection (observability + tests).
    pub async fn inbound_peers(&self) -> Vec<PeerId> {
        self.inbound
            .lock()
            .await
            .keys()
            .cloned()
            .map(PeerId::from)
            .collect()
    }

    /// Build our server identity + the mutual-TLS server config, bind the listener, and
    /// spawn its accept loop. Called by `start` when a listen addr is configured; a bind
    /// failure is surfaced (not fatal — outbound still works).
    async fn spawn_listener(&self, addr: SocketAddr, events: EventSink) -> Result<(), HostError> {
        let (cert, pkcs8) = host_identity(&self.pairing, &self.announce.device_id)?;
        let server_cfg = tls::build_server_config_with_client_auth(&cert, &pkcs8)
            .ok_or_else(|| HostError::Transport("server_config".into()))?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| HostError::Transport(format!("bind: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| HostError::Transport(format!("local_addr: {e}")))?;
        *self.bound_addr.lock().await = Some(bound);
        let (stop_tx, stop_rx) = oneshot::channel();
        *self.listen_shutdown.lock().await = Some(stop_tx);
        *self.listen_task.lock().await = Some(tokio::spawn(run_listener(
            listener,
            Arc::new(server_cfg),
            Arc::clone(&self.pairing),
            Arc::clone(&self.inbound),
            events,
            stop_rx,
        )));
        Ok(())
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
        *self.disc_task.lock().await = Some(tokio::spawn(discovery.run(events.clone(), stop_rx)));
        // Inbound listener (best-effort): bind the configured port and accept
        // peer-initiated links. A bind failure is surfaced as a TransportError but does
        // NOT fail `start` — the outbound (`open`) path stays usable regardless.
        if let Some(addr) = self.listen_addr {
            if let Err(e) = self.spawn_listener(addr, events.clone()).await {
                let _ = events.send(HostEvent::TransportError(format!("listen: {e}")));
            }
        }
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
        // Stop the inbound accept loop and tear down accepted connections.
        if let Some(tx) = self.listen_shutdown.lock().await.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.listen_task.lock().await.take() {
            let _ = task.await;
        }
        for (_id, conn) in self.inbound.lock().await.drain() {
            conn.close().await;
        }
        *self.bound_addr.lock().await = None;
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

/// Accept inbound peer links until `stop` fires. Each accepted TCP connection is handed to
/// [`handle_inbound`] on its own task, so a slow or hostile handshake can't stall the loop
/// or block other peers. A transient `accept` error is skipped; the loop keeps listening.
async fn run_listener(
    listener: TcpListener,
    server_cfg: Arc<rustls::ServerConfig>,
    pairing: Arc<PairingStore>,
    inbound: Arc<AsyncMutex<HashMap<String, Box<dyn Connection>>>>,
    sink: EventSink,
    mut stop: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => {
                let tcp = match accepted {
                    Ok((tcp, _addr)) => tcp,
                    Err(_) => continue, // transient accept error — keep listening
                };
                tokio::spawn(handle_inbound(
                    tcp,
                    Arc::clone(&server_cfg),
                    Arc::clone(&pairing),
                    Arc::clone(&inbound),
                    sink.clone(),
                ));
            }
        }
    }
}

/// Authenticate and register one inbound peer link:
///
/// 1. Complete the **mutual-TLS** handshake (the peer presents its identity cert).
/// 2. Run the **identity-first handshake** — read the peer's first frame, which must be a
///    `kdeconnect.identity` packet, to learn the *claimed* device id.
/// 3. **Bind** the claimed id to cryptographic proof: the device must be paired, and the
///    fingerprint of the cert it presented in step 1 must equal the value pinned at pair
///    time. This is what stops a peer from spoofing another device's id.
///
/// On success it emits `Connected` and stores the framed [`LanConnection`] (so `send_to`
/// can reply and the read loop surfaces inbound `Packet`s). Every rejection is surfaced as
/// a `TransportError` carrying a stable token, and the link is dropped.
async fn handle_inbound(
    tcp: TcpStream,
    server_cfg: Arc<rustls::ServerConfig>,
    pairing: Arc<PairingStore>,
    inbound: Arc<AsyncMutex<HashMap<String, Box<dyn Connection>>>>,
    sink: EventSink,
) {
    let acceptor = TlsAcceptor::from(server_cfg);
    let mut tls = match acceptor.accept(tcp).await {
        Ok(t) => t,
        Err(e) => {
            let _ = sink.send(HostEvent::TransportError(format!("inbound_tls: {e}")));
            return;
        }
    };
    // The peer's presented client cert (mutual TLS) — its fingerprint is the identity proof.
    let presented_fp = {
        let (_io, conn) = tls.get_ref();
        conn.peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| tls::compute_fingerprint(cert.as_ref()))
    };
    // Identity-first handshake: learn who's claiming to connect.
    let (packet, decoder) = match read_first_frame(&mut tls).await {
        Ok(x) => x,
        Err(e) => {
            let _ = sink.send(HostEvent::TransportError(format!("inbound_identity: {e}")));
            return;
        }
    };
    let announce = match announce_from_identity(packet) {
        Ok(a) => a,
        Err(e) => {
            let _ = sink.send(HostEvent::TransportError(format!("inbound_identity: {e}")));
            return;
        }
    };
    let peer_id = announce.device_id.clone();
    // Must be a paired device.
    let pinned = match pairing.get(&peer_id) {
        Some(rec) => rec.fingerprint.clone(),
        None => {
            let _ = sink.send(HostEvent::TransportError(format!(
                "inbound_not_paired: {peer_id}"
            )));
            return;
        }
    };
    // Bind the claimed identity to the presented cert. An empty pin means the device was
    // recorded without a fingerprint (first-pair not yet completed) — the live listener
    // refuses it; the pairing flow, not this listener, owns first-pair.
    if pinned.is_empty() {
        let _ = sink.send(HostEvent::TransportError(format!(
            "inbound_unpinned: {peer_id}"
        )));
        return;
    }
    if presented_fp.as_deref() != Some(pinned.as_str()) {
        let _ = sink.send(HostEvent::TransportError(format!(
            "kdc-fingerprint-mismatch: {peer_id}"
        )));
        return;
    }
    // Authenticated. Wrap the remaining stream (the seeded decoder carries any bytes read
    // past the identity frame), register the link, then announce it. Registering before
    // `Connected` means a consumer can `send_to` the moment it sees the event.
    let peer = PeerId::from(peer_id.clone());
    let conn: Box<dyn Connection> = Box::new(LanConnection::new_seeded(
        tls,
        decoder,
        peer.clone(),
        sink.clone(),
    ));
    inbound.lock().await.insert(peer_id, conn);
    let _ = sink.send(HostEvent::Connected(peer));
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

    // ── Inbound listener (host increment 3b.2e) ──────────────────────────────

    /// A `kdeconnect.identity` packet carrying `a` — the first frame a peer sends after
    /// the inbound TLS handshake (same envelope as the UDP identity broadcast).
    fn identity_packet(a: &Announce) -> Packet {
        Packet {
            id: 1,
            kind: "kdeconnect.identity".to_string(),
            body: serde_json::to_value(a).unwrap(),
            ..Default::default()
        }
    }

    /// Build a listening host transport over a fresh pairing store (mutated by `setup` to
    /// add paired devices), start it, and return it plus its bound listener addr + stream.
    async fn start_listening_host(
        setup: impl FnOnce(&mut PairingStore),
    ) -> (LanTransport, SocketAddr, EventStream) {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = PairingStore::open(tmp.path()).unwrap();
        setup(&mut store);
        let pairing = Arc::new(store);
        let discovery = UdpDiscovery::bind("127.0.0.1:0".parse().unwrap(), announce("self"))
            .await
            .unwrap();
        let transport = LanTransport::new(announce("self"), discovery, pairing)
            .with_listen_addr("127.0.0.1:0".parse().unwrap());
        let (sink, stream) = EventStream::channel();
        transport.start(sink).await.unwrap();
        let addr = transport
            .local_listen_addr()
            .await
            .expect("listener bound after start");
        (transport, addr, stream)
    }

    /// A peer that connects to `addr` presenting `cert`/`pkcs8` (mutual TLS, accepting any
    /// server cert), then sends its `kdeconnect.identity` frame for `device_id`. Returns
    /// the framed connection (kept alive by the caller) + its stream (server→peer packets).
    #[allow(clippy::type_complexity)]
    async fn connect_as(
        addr: SocketAddr,
        device_id: &str,
        cert: &[u8],
        pkcs8: &[u8],
    ) -> (
        LanConnection<tokio_rustls::client::TlsStream<TcpStream>>,
        EventStream,
    ) {
        let tls = crate::tls::connect_tls_with_identity(addr, "self", None, cert, pkcs8)
            .await
            .expect("client mutual-tls connect");
        let (sink, stream) = EventStream::channel();
        let conn = LanConnection::new(tls, PeerId::from("self"), sink);
        conn.send(identity_packet(&announce(device_id)))
            .await
            .expect("send identity frame");
        (conn, stream)
    }

    #[tokio::test]
    async fn inbound_listener_accepts_paired_peer_and_round_trips() {
        // A paired phone (pinned to its cert fingerprint) initiates a link: the listener
        // completes mutual TLS, reads the identity frame, binds the presented fingerprint
        // to the pinned value, and surfaces Connected + the phone's packets. send_to replies.
        let phone_pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let phone_cert = crate::keygen::issue_identity_cert(&phone_pkcs8, "phone-1").unwrap();
        let phone_fp = compute_fingerprint(&phone_cert);

        let (transport, addr, mut host_stream) = start_listening_host(|store| {
            store
                .pair(DeviceRecord {
                    device_id: "phone-1".into(),
                    device_name: "Phone".into(),
                    paired_at_ms: 1,
                    fingerprint: phone_fp.clone(),
                })
                .unwrap();
        })
        .await;

        let (client, mut client_stream) =
            connect_as(addr, "phone-1", &phone_cert, &phone_pkcs8).await;

        // The host announces the authenticated inbound link.
        let connected = tokio::time::timeout(std::time::Duration::from_secs(2), host_stream.recv())
            .await
            .expect("connected before timeout");
        assert!(matches!(connected, Some(HostEvent::Connected(p)) if p.as_str() == "phone-1"));

        // A ping from the phone surfaces as a Packet attributed to phone-1.
        client
            .send(plugins::ping_packet(7, "hi".into()))
            .await
            .unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), host_stream.recv())
            .await
            .expect("packet before timeout");
        assert!(
            matches!(got, Some(HostEvent::Packet { peer, packet }) if peer.as_str() == "phone-1" && packet.id == 7)
        );

        // Bidirectional: send_to reaches the phone's own stream.
        transport
            .send_to(
                &PeerId::from("phone-1"),
                plugins::ping_packet(8, "yo".into()),
            )
            .await
            .expect("send_to the inbound peer");
        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), client_stream.recv())
            .await
            .expect("reply before timeout");
        assert!(matches!(reply, Some(HostEvent::Packet { packet, .. }) if packet.id == 8));

        assert_eq!(
            transport.inbound_peers().await,
            vec![PeerId::from("phone-1")]
        );
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn inbound_listener_rejects_unpaired_peer() {
        // An unpaired device id is refused after the identity handshake; nothing registers.
        let pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let cert = crate::keygen::issue_identity_cert(&pkcs8, "stranger").unwrap();

        let (transport, addr, mut host_stream) = start_listening_host(|_store| {}).await;
        let (_client, _cs) = connect_as(addr, "stranger", &cert, &pkcs8).await;

        let evt = tokio::time::timeout(std::time::Duration::from_secs(2), host_stream.recv())
            .await
            .expect("an event before timeout");
        assert!(
            matches!(evt, Some(HostEvent::TransportError(m)) if m.contains("inbound_not_paired"))
        );
        assert!(transport.inbound_peers().await.is_empty());
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn inbound_listener_rejects_fingerprint_mismatch() {
        // phone-1 is paired, but pinned to a DIFFERENT cert than the one the connecting
        // client presents → a spoofed identity. The fingerprint binding rejects it.
        let real_pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let real_cert = crate::keygen::issue_identity_cert(&real_pkcs8, "phone-1").unwrap();
        let pinned_fp = compute_fingerprint(&real_cert);

        let imposter_pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let imposter_cert = crate::keygen::issue_identity_cert(&imposter_pkcs8, "phone-1").unwrap();

        let (transport, addr, mut host_stream) = start_listening_host(|store| {
            store
                .pair(DeviceRecord {
                    device_id: "phone-1".into(),
                    device_name: "Phone".into(),
                    paired_at_ms: 1,
                    fingerprint: pinned_fp.clone(),
                })
                .unwrap();
        })
        .await;

        let (_client, _cs) = connect_as(addr, "phone-1", &imposter_cert, &imposter_pkcs8).await;

        let evt = tokio::time::timeout(std::time::Duration::from_secs(2), host_stream.recv())
            .await
            .expect("an event before timeout");
        assert!(
            matches!(evt, Some(HostEvent::TransportError(m)) if m.contains("kdc-fingerprint-mismatch"))
        );
        assert!(transport.inbound_peers().await.is_empty());
        transport.shutdown().await;
    }
}
