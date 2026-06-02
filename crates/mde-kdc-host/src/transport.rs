//! The `Transport` abstraction and an in-process loopback implementation.
//!
//! A [`Transport`] is the per-platform plug-in point of the host layer — the LAN
//! transport (UDP 1716 discovery + rustls TCP, a later increment) and the
//! in-process [`LoopbackTransport`] here both implement it. Inbound traffic flows
//! uniformly onto the single host [`EventSink`](crate::EventSink) (the "event
//! stream -> Surface" spine); outbound traffic goes per-peer through a
//! [`Connection`]. Keeping the trait object-safe (via `async-trait`) lets the
//! host hold `Box<dyn Transport>` / `Box<dyn Connection>` and swap transports.

use async_trait::async_trait;
use std::sync::Mutex;

use mde_kdc_proto::{codec, discovery::Announce, wire::Packet};

use crate::error::HostError;
use crate::event::{EventSink, HostEvent};
use crate::PeerId;

/// A transport: owns discovery + connection setup and emits every inbound event
/// onto the shared event stream. Object-safe so the host can hold
/// `Box<dyn Transport>`.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Start the transport — bind sockets / spawn listeners (a no-op for the
    /// loopback) and begin emitting [`HostEvent`]s onto `events`. Returns once
    /// the transport is live; background work continues on tasks it owns.
    async fn start(&self, events: EventSink) -> Result<(), HostError>;

    /// Open (or reuse) an authenticated connection to a peer. The LAN transport
    /// resolves the TCP target, runs the rustls + RSA handshake, and seeds the
    /// session; the loopback returns an in-memory echo link.
    async fn open(&self, peer: &PeerId) -> Result<Box<dyn Connection>, HostError>;

    /// This host's own identity payload (advertised on discovery, sent as the
    /// `kdeconnect.identity` body).
    fn local_announce(&self) -> &Announce;

    /// Stop listeners and drop background work. Idempotent.
    async fn shutdown(&self);
}

/// One live duplex link to a single peer. Inbound packets are drained onto the
/// event stream by the transport, so a `Connection` is the per-peer write +
/// teardown handle the router holds.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Which peer this connection talks to.
    fn peer(&self) -> &PeerId;

    /// Send one packet to the peer (frames + — on the LAN transport —
    /// session-encrypts internally). The caller sets `Packet.id` to the
    /// millisecond Unix timestamp (also the dual-send dedupe key).
    async fn send(&self, packet: Packet) -> Result<(), HostError>;

    /// Close this connection. Future `send`s on it will error.
    async fn close(&self);
}

/// An in-process loopback transport for tests and headless development: `open`
/// hands back a connection whose `send` echoes the packet straight back onto the
/// event stream as a `HostEvent::Packet`, round-tripping through the real frame
/// codec ([`codec::encode_frame`] + [`codec::FrameDecoder`]). It needs no
/// sockets, so the whole host/router stack can be exercised on `#[tokio::test]`.
pub struct LoopbackTransport {
    announce: Announce,
    sink: Mutex<Option<EventSink>>,
}

impl LoopbackTransport {
    /// A loopback transport advertising `announce`.
    #[must_use]
    pub fn new(announce: Announce) -> Self {
        Self {
            announce,
            sink: Mutex::new(None),
        }
    }

    fn sink(&self) -> Result<EventSink, HostError> {
        self.sink
            .lock()
            .expect("loopback sink mutex poisoned")
            .clone()
            .ok_or_else(|| HostError::Transport("loopback not started".into()))
    }
}

#[async_trait]
impl Transport for LoopbackTransport {
    async fn start(&self, events: EventSink) -> Result<(), HostError> {
        *self.sink.lock().expect("loopback sink mutex poisoned") = Some(events);
        Ok(())
    }

    async fn open(&self, peer: &PeerId) -> Result<Box<dyn Connection>, HostError> {
        let sink = self.sink()?;
        // A real transport emits Connected after the handshake; loopback is
        // "connected" immediately.
        let _ = sink.send(HostEvent::Connected(peer.clone()));
        Ok(Box::new(LoopbackConnection {
            peer: peer.clone(),
            sink,
        }))
    }

    fn local_announce(&self) -> &Announce {
        &self.announce
    }

    async fn shutdown(&self) {
        *self.sink.lock().expect("loopback sink mutex poisoned") = None;
    }
}

/// A loopback peer link: `send` echoes the packet back as an inbound event.
struct LoopbackConnection {
    peer: PeerId,
    sink: EventSink,
}

#[async_trait]
impl Connection for LoopbackConnection {
    fn peer(&self) -> &PeerId {
        &self.peer
    }

    async fn send(&self, packet: Packet) -> Result<(), HostError> {
        // Round-trip through the real frame codec so framing is exercised, then
        // echo the decoded packet back as if the peer had sent it.
        let frame = codec::encode_frame(&packet)?;
        let mut decoder = codec::FrameDecoder::new();
        decoder.feed(frame.as_bytes());
        if let Some(decoded) = decoder.next_frame()? {
            let _ = self.sink.send(HostEvent::Packet {
                peer: self.peer.clone(),
                packet: decoded,
            });
        }
        Ok(())
    }

    async fn close(&self) {
        let _ = self.sink.send(HostEvent::Disconnected(self.peer.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventStream;
    use mde_kdc_proto::{discovery::DeviceType, plugins};

    fn announce() -> Announce {
        Announce {
            device_id: "self".into(),
            device_name: "Host".into(),
            device_type: DeviceType::Desktop,
            protocol_version: 7,
            incoming_capabilities: vec![],
            outgoing_capabilities: vec![],
        }
    }

    #[tokio::test]
    async fn loopback_echoes_packet_through_framing() {
        let transport = LoopbackTransport::new(announce());
        assert_eq!(transport.local_announce().device_id, "self");

        let (sink, mut stream) = EventStream::channel();
        transport.start(sink).await.unwrap();

        let conn = transport.open(&PeerId::from("peer-1")).await.unwrap();
        assert_eq!(conn.peer().as_str(), "peer-1");
        // open() signals Connected first.
        assert!(
            matches!(stream.recv().await, Some(HostEvent::Connected(p)) if p.as_str() == "peer-1")
        );

        // Send a ping; it should round-trip the codec and echo back as a Packet.
        let ping = plugins::ping_packet(123, "hi".into());
        conn.send(ping.clone()).await.unwrap();
        match stream.recv().await {
            Some(HostEvent::Packet { peer, packet }) => {
                assert_eq!(peer.as_str(), "peer-1");
                assert_eq!(packet.id, 123);
                assert_eq!(packet.kind, ping.kind);
            }
            other => panic!("expected Packet, got {other:?}"),
        }

        conn.close().await;
        assert!(matches!(
            stream.recv().await,
            Some(HostEvent::Disconnected(_))
        ));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn open_before_start_errors() {
        let transport = LoopbackTransport::new(announce());
        // `unwrap_err` would need `Box<dyn Connection>: Debug`, which it isn't —
        // match on the result instead.
        let result = transport.open(&PeerId::from("x")).await;
        assert!(matches!(result, Err(HostError::Transport(_))));
    }
}
