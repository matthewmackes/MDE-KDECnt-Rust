//! Host layer for the MDE KDE Connect stack.
//!
//! `mde-kdc-proto` is the pure protocol layer (codec, crypto, discovery,
//! plugins — zero I/O). This crate is the **host**: the side that touches the
//! filesystem and (later) the network. The architecture, per the workspace
//! README, is:
//!
//! ```text
//! Protocol  ->  Transport (trait)  ->  Host / Router  ->  event stream  ->  Surface
//! ```
//!
//! This first increment lands the non-networking foundation — the [`PeerId`]
//! newtype, the [`HostError`] type, the [`event`] stream (`HostEvent` +
//! `EventStream`), and the on-disk [`pairing`] store (`PairingStore`, which also
//! implements the protocol's [`mde_kdc_proto::crypto::KeyStore`]). The live LAN
//! transport (UDP 1716 discovery + rustls TCP) and the `Transport` trait it
//! plugs into are deferred to later increments and are built against these
//! pieces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod event;
pub mod pairing;
pub mod transport;

pub use error::HostError;
pub use event::{EventSink, EventStream, HostEvent};
pub use pairing::{DeviceRecord, PairingStore};
pub use transport::{Connection, LoopbackTransport, Transport};

/// The stable identity of a peer — the protocol's `Announce.device_id`.
///
/// A thin newtype so peer ids don't get confused with arbitrary strings as they
/// flow through the event stream, the pairing store, and (later) the transport.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub String);

impl PeerId {
    /// Borrow the underlying device-id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        PeerId(s)
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        PeerId(s.to_string())
    }
}
