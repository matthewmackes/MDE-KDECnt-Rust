//! The host-layer error type.

use thiserror::Error;

/// Errors from the host layer (pairing store + event stream now; the transport
/// later). Wraps the protocol crate's per-module errors alongside the host's own
/// I/O, serialization, and key-generation failures.
#[derive(Debug, Error)]
pub enum HostError {
    /// A filesystem operation on the pairing store failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Serializing the pairing store (`devices.toml`) failed.
    #[error("toml: {0}")]
    TomlSer(#[from] toml::ser::Error),

    /// A protocol-crypto operation (signing, or loading the identity key)
    /// failed.
    #[error("crypto: {0}")]
    Crypto(#[from] mde_kdc_proto::crypto::CryptoError),

    /// JSON (de)serialization of a packet or frame failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Decoding an inbound wire frame failed.
    #[error("codec: {0}")]
    Codec(#[from] mde_kdc_proto::codec::DecodeError),

    /// A transport-level condition (e.g. used before `start`, or a peer that
    /// isn't reachable).
    #[error("transport: {0}")]
    Transport(String),

    /// RSA key generation or PKCS#8 / PKCS#1 encoding failed. The host owns
    /// keygen because the protocol crate intentionally ships none (ring 0.17 has
    /// no RSA keygen).
    #[error("keygen: {0}")]
    Keygen(String),

    /// No config directory could be resolved — neither `$XDG_CONFIG_HOME` nor
    /// `$HOME` is set.
    #[error("no config directory ($XDG_CONFIG_HOME / $HOME unset)")]
    NoConfigDir,
}
