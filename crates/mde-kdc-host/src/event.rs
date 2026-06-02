//! The host event stream — everything the host surfaces to the Surface (the
//! iced UI or a D-Bus bridge), in the order it happened.

use mde_kdc_proto::{discovery::Announce, wire::Packet};
use tokio::sync::mpsc;

use crate::PeerId;

/// One thing the host surfaces to the Surface, in arrival order.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// A peer appeared (or refreshed) in discovery.
    PeerDiscovered(Announce),
    /// A previously-discovered peer aged out of the discovery registry.
    PeerLost(PeerId),
    /// An authenticated, session-encrypted connection to a peer came up.
    Connected(PeerId),
    /// A peer connection dropped.
    Disconnected(PeerId),
    /// A decoded inbound packet from a peer (post-decrypt, pre-plugin-dispatch).
    Packet {
        /// Which peer sent it.
        peer: PeerId,
        /// The decoded protocol packet.
        packet: Packet,
    },
    /// A transport / codec / crypto problem worth surfacing, rendered to its
    /// stable machine token.
    TransportError(String),
}

/// The producer half of the event stream, held by each transport.
pub type EventSink = mpsc::UnboundedSender<HostEvent>;

/// The consumer half of the event stream, drained by the Surface.
///
/// Unbounded so a slow Surface never stalls the transport reader; the wrapper
/// hides the channel kind so a future switch to a bounded, back-pressured
/// channel won't change callers.
pub struct EventStream(mpsc::UnboundedReceiver<HostEvent>);

impl EventStream {
    /// Create a fresh `(sink, stream)` pair.
    #[must_use]
    pub fn channel() -> (EventSink, EventStream) {
        let (tx, rx) = mpsc::unbounded_channel();
        (tx, EventStream(rx))
    }

    /// Await the next host event. Returns `None` only once *every* sink clone is
    /// dropped — the transport's own [`EventSink`] and every per-connection clone
    /// it handed out — since [`EventSink`] is a cloneable mpsc sender. A
    /// transport's `shutdown` alone won't close the stream while a `Connection`
    /// still holds a clone.
    pub async fn recv(&mut self) -> Option<HostEvent> {
        self.0.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mde_kdc_proto::discovery::{Announce, DeviceType};

    fn announce(id: &str) -> Announce {
        Announce {
            device_id: id.to_string(),
            device_name: "Test".to_string(),
            device_type: DeviceType::Phone,
            protocol_version: 7,
            incoming_capabilities: vec![],
            outgoing_capabilities: vec![],
        }
    }

    #[tokio::test]
    async fn events_arrive_in_order_then_close() {
        let (sink, mut stream) = EventStream::channel();
        sink.send(HostEvent::PeerDiscovered(announce("a"))).unwrap();
        sink.send(HostEvent::Connected(PeerId::from("a"))).unwrap();
        sink.send(HostEvent::Disconnected(PeerId::from("a")))
            .unwrap();
        sink.send(HostEvent::TransportError("frame_too_large".into()))
            .unwrap();

        assert!(
            matches!(stream.recv().await, Some(HostEvent::PeerDiscovered(a)) if a.device_id == "a")
        );
        assert!(matches!(stream.recv().await, Some(HostEvent::Connected(p)) if p.as_str() == "a"));
        assert!(matches!(
            stream.recv().await,
            Some(HostEvent::Disconnected(_))
        ));
        assert!(
            matches!(stream.recv().await, Some(HostEvent::TransportError(t)) if t == "frame_too_large")
        );

        // Once every sink is dropped, the stream closes.
        drop(sink);
        assert!(stream.recv().await.is_none());
    }
}
