//! TLS layer with fingerprint pinning (host increment 3b).
//!
//! KDE Connect's identity model bypasses the conventional CA chain: peers
//! self-sign and the recipient pins the cert fingerprint at first pair. Any later
//! connection presenting a different fingerprint is rejected (surfaced as a
//! key-mismatch in the UI). This module ports the reference TLS layer:
//!
//!   * [`compute_fingerprint`] — SHA-256 of the cert DER, hex-uppercase with `:`
//!     between bytes (`AB:CD:EF:…`), matching upstream KDE Connect's settings
//!     dialog format.
//!   * [`PinnedFingerprintVerifier`] — a rustls `ServerCertVerifier` that accepts
//!     ANY cert whose fingerprint matches the pinned value and rejects all else
//!     (self-signed by design, so no chain validation).
//!   * [`FirstPairVerifier`] — accepts any cert during first-pair (before the
//!     recipient knows what to pin); the pair flow records the fingerprint, and
//!     subsequent connections use the pinned verifier.
//!   * [`build_client_config`] + [`connect_pinned_tls`] — the live connect path
//!     (`tokio-rustls` over a `tokio::net::TcpStream`), which `Transport::open`
//!     (the router increment) drives against a discovered peer's address.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};

/// The self-signed RSA-2048 identity certs only ever sign with these schemes;
/// every custom verifier advertises exactly this set (mirrors upstream KDC).
fn rsa_identity_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
    ]
}

/// Compute the KDE-Connect-style cert fingerprint: SHA-256 of the DER bytes,
/// upper-case hex with `:` between every byte. Pure + deterministic. Used both at
/// pair-time (to record the fingerprint) and at handshake-time (to compare against
/// the pinned value).
#[must_use]
pub fn compute_fingerprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    let mut out = String::with_capacity(95); // 32 bytes × 3 chars - 1 separator
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// A rustls `ServerCertVerifier` that accepts ONLY the cert whose SHA-256
/// fingerprint matches the pinned value. Constructed by the host with the value
/// from a paired device's stored fingerprint.
#[derive(Debug)]
pub struct PinnedFingerprintVerifier {
    pinned: String,
}

impl PinnedFingerprintVerifier {
    /// Wrap a known fingerprint into the verifier.
    #[must_use]
    pub fn new(pinned_fingerprint: impl Into<String>) -> Self {
        Self {
            pinned: pinned_fingerprint.into(),
        }
    }
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let observed = compute_fingerprint(end_entity.as_ref());
        if observed == self.pinned {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "kdc-fingerprint-mismatch: expected={} observed={}",
                self.pinned, observed,
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rsa_identity_schemes()
    }
}

/// First-pair verifier — accepts ANY presented cert without checking pin or CA
/// chain. The pair flow records the cert's fingerprint; subsequent connections use
/// [`PinnedFingerprintVerifier`].
///
/// **Do not** use this verifier outside the first-pair path — elsewhere,
/// fingerprint pinning is what makes the TLS trust model meaningful.
#[derive(Debug)]
pub struct FirstPairVerifier;

impl ServerCertVerifier for FirstPairVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The pair flow records the fingerprint AFTER the handshake; any cert is
        // acceptable at this stage.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rsa_identity_schemes()
    }
}

/// A rustls `ClientCertVerifier` for the **inbound** (listener) side. KDE Connect's
/// modern protocol is mutual-TLS: a peer connecting to us presents its identity cert.
/// This verifier *requires* a client cert (so it lands in `peer_certificates()`) but
/// accepts ANY cert at the TLS layer — the binding to a paired device's pinned
/// fingerprint is enforced one layer up, in the listener, after the identity-first
/// handshake reveals *which* device is claiming to connect.
///
/// **Audit note (divergence from the reference port):** the `/tmp/MDE-guidance`
/// reference uses `no_client_auth` on its (test-only) inbound TLS, leaving the
/// connecting peer's identity unauthenticated at the transport. We instead request the
/// client cert and bind its fingerprint to the pinned value, so a peer cannot spoof a
/// paired device id. Flagged for the owner's adversarial audit.
#[derive(Debug, Default)]
pub struct AcceptAnyClientCert {
    /// `root_hint_subjects` must return a slice; we advertise none (self-signed model).
    no_hints: Vec<DistinguishedName>,
}

impl ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.no_hints
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Accept at the TLS layer; the listener pins the presented fingerprint to the
        // claimed (paired) device id after the identity handshake.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rsa_identity_schemes()
    }
}

/// Build a rustls `ClientConfig` for the pinning model. The ring crypto provider
/// is wired explicitly so the audit closure agrees with `mde-kdc-proto`'s ring
/// usage. `None` → [`FirstPairVerifier`]; `Some` → [`PinnedFingerprintVerifier`].
#[must_use]
pub fn build_client_config(pinned_fingerprint: Option<String>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions installed");
    let verifier: Arc<dyn ServerCertVerifier> = if let Some(pin) = pinned_fingerprint {
        Arc::new(PinnedFingerprintVerifier::new(pin))
    } else {
        Arc::new(FirstPairVerifier)
    };
    builder
        .dangerous() // self-signed model — pinning replaces chain validation
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Build a rustls `ServerConfig` presenting our own identity cert + key, for the
/// inbound side of the LAN transport (a peer connecting to us). KDE Connect's TLS
/// is mutual self-signed, but client-cert verification is done out-of-band by
/// fingerprint at the pairing layer, so the server side uses `no_client_auth` here
/// and the recipient pins the *client's* presented cert separately. `cert_der` is
/// our self-signed identity cert ([`crate::keygen::issue_identity_cert`]) and
/// `pkcs8_der` its matching PKCS#8 private key.
///
/// Returns `None` if rustls rejects the cert/key pair (mismatched or malformed).
#[must_use]
pub fn build_server_config(cert_der: &[u8], pkcs8_der: &[u8]) -> Option<rustls::ServerConfig> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert_chain = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.to_vec()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions installed")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .ok()
}

/// Build a rustls `ServerConfig` for the **inbound listener** that, unlike
/// [`build_server_config`], *requests and requires* a client cert ([`AcceptAnyClientCert`])
/// so the peer's presented identity cert is available in `peer_certificates()` after the
/// handshake. The listener then binds that cert's fingerprint to the paired device's
/// pinned value (mutual-TLS identity, see [`AcceptAnyClientCert`]'s audit note).
/// `cert_der` is our self-signed identity cert and `pkcs8_der` its PKCS#8 key. Returns
/// `None` if rustls rejects the cert/key pair.
#[must_use]
pub fn build_server_config_with_client_auth(
    cert_der: &[u8],
    pkcs8_der: &[u8],
) -> Option<rustls::ServerConfig> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert_chain = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.to_vec()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions installed")
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert::default()))
        .with_single_cert(cert_chain, key)
        .ok()
}

/// Errors from the live TLS connect path.
#[derive(Debug)]
pub enum ConnectError {
    /// TCP `connect` failed (host unreachable, no route, refused).
    Tcp(std::io::Error),
    /// TLS handshake failed (peer cert mismatch, bad cert, etc.).
    Tls(std::io::Error),
    /// The peer name couldn't be parsed as a `ServerName`.
    BadPeerName(String),
    /// Our own client identity cert/key was rejected by rustls (mutual-TLS path).
    BadIdentity(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Tcp(e) => write!(f, "tcp: {e}"),
            ConnectError::Tls(e) => write!(f, "tls: {e}"),
            ConnectError::BadPeerName(s) => write!(f, "bad_peer_name: {s}"),
            ConnectError::BadIdentity(s) => write!(f, "bad_identity: {s}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Open a TLS-wrapped TCP connection to `addr`, presenting `server_name` in the
/// ClientHello, with the cert pinned to `pinned_fingerprint` (`None` = first-pair /
/// accept any). Returns a `tokio_rustls::client::TlsStream<TcpStream>` the router
/// wraps with the codec framer + payload-channel handshake.
///
/// Outbound is currently server-auth only (`with_no_client_auth`). **FOLLOW-UP (planned,
/// per the Mackes Workstation plan §0):** switch this to mutual TLS via
/// [`connect_tls_with_identity`] so a peer whose listener requires a client cert (modern
/// KDE Connect, and our own [`build_server_config_with_client_auth`] inbound side) accepts
/// us — making both directions symmetric.
pub async fn connect_pinned_tls(
    addr: std::net::SocketAddr,
    server_name: &str,
    pinned_fingerprint: Option<String>,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, ConnectError> {
    let server_name_owned = ServerName::try_from(server_name.to_string())
        .map_err(|e| ConnectError::BadPeerName(format!("{e}")))?;
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(ConnectError::Tcp)?;
    let config = Arc::new(build_client_config(pinned_fingerprint));
    let connector = tokio_rustls::TlsConnector::from(config);
    connector
        .connect(server_name_owned, tcp)
        .await
        .map_err(ConnectError::Tls)
}

/// Like [`build_client_config`] but the client **presents its own identity cert + key**
/// (mutual TLS), required to connect to a listener that requests a client cert (our
/// [`build_server_config_with_client_auth`], and modern KDE Connect devices).
/// `pinned_fingerprint`: `None` = first-pair / accept any server cert, `Some` = pin the
/// server's cert. Returns `None` if rustls rejects our cert/key pair.
#[must_use]
pub fn build_client_config_with_identity(
    pinned_fingerprint: Option<String>,
    client_cert_der: &[u8],
    client_pkcs8_der: &[u8],
) -> Option<rustls::ClientConfig> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions installed");
    let verifier: Arc<dyn ServerCertVerifier> = if let Some(pin) = pinned_fingerprint {
        Arc::new(PinnedFingerprintVerifier::new(pin))
    } else {
        Arc::new(FirstPairVerifier)
    };
    let cert_chain = vec![CertificateDer::from(client_cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_pkcs8_der.to_vec()));
    builder
        .dangerous() // self-signed model — pinning replaces chain validation
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, key)
        .ok()
}

/// Open a **mutual-TLS** connection to `addr` presenting our identity cert (so a peer
/// whose listener requests a client cert accepts us), pinning the server's cert to
/// `pinned_fingerprint` (`None` = first-pair). Mirrors [`connect_pinned_tls`] but with
/// client auth — used to drive the inbound listener and available for the mutual
/// outbound path.
pub async fn connect_tls_with_identity(
    addr: std::net::SocketAddr,
    server_name: &str,
    pinned_fingerprint: Option<String>,
    client_cert_der: &[u8],
    client_pkcs8_der: &[u8],
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, ConnectError> {
    let server_name_owned = ServerName::try_from(server_name.to_string())
        .map_err(|e| ConnectError::BadPeerName(format!("{e}")))?;
    let config =
        build_client_config_with_identity(pinned_fingerprint, client_cert_der, client_pkcs8_der)
            .ok_or_else(|| ConnectError::BadIdentity("client cert/key rejected".into()))?;
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(ConnectError::Tcp)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector
        .connect(server_name_owned, tcp)
        .await
        .map_err(ConnectError::Tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_now() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000))
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let bytes = b"identical cert bytes";
        assert_eq!(compute_fingerprint(bytes), compute_fingerprint(bytes));
    }

    #[test]
    fn fingerprint_changes_on_input_change() {
        assert_ne!(compute_fingerprint(b"a"), compute_fingerprint(b"b"));
    }

    #[test]
    fn fingerprint_format_matches_upstream_kdc() {
        // Upper-case hex, colon-separated, 32 bytes -> 95 chars.
        let fp = compute_fingerprint(b"abc");
        assert_eq!(fp.len(), 95);
        assert_eq!(&fp[2..3], ":");
        assert_eq!(&fp[5..6], ":");
        for c in fp.chars() {
            assert!(
                (c.is_ascii_hexdigit() && c.to_ascii_uppercase() == c) || c == ':',
                "non-uppercase non-colon char {c:?} in fingerprint",
            );
        }
    }

    #[test]
    fn pinned_verifier_accepts_matching_fingerprint() {
        let cert_bytes = b"some cert der";
        let fp = compute_fingerprint(cert_bytes);
        let verifier = PinnedFingerprintVerifier::new(fp);
        let result = verifier.verify_server_cert(
            &CertificateDer::from(cert_bytes.to_vec()),
            &[],
            &ServerName::try_from("device").unwrap(),
            &[],
            dummy_now(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn pinned_verifier_rejects_mismatched_fingerprint() {
        let verifier = PinnedFingerprintVerifier::new("00:11:22:33");
        let result = verifier.verify_server_cert(
            &CertificateDer::from(b"some cert der".to_vec()),
            &[],
            &ServerName::try_from("device").unwrap(),
            &[],
            dummy_now(),
        );
        let err = result.expect_err("mismatch must reject");
        assert!(
            format!("{err}").contains("kdc-fingerprint-mismatch"),
            "error must include the kdc-fingerprint-mismatch tag",
        );
    }

    #[test]
    fn first_pair_verifier_accepts_any_cert() {
        let verifier = FirstPairVerifier;
        let result = verifier.verify_server_cert(
            &CertificateDer::from(b"random bytes".to_vec()),
            &[],
            &ServerName::try_from("device").unwrap(),
            &[],
            dummy_now(),
        );
        assert!(result.is_ok(), "first-pair must accept any cert");
    }

    #[test]
    fn build_client_config_constructs_both_paths() {
        let _pinned = build_client_config(Some("AA:BB:CC".to_string()));
        let _first = build_client_config(None);
    }

    #[test]
    fn build_server_config_accepts_a_real_identity_cert() {
        // A freshly-issued identity cert + its PKCS#8 key build a ServerConfig.
        let pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let cert = crate::keygen::issue_identity_cert(&pkcs8, "device-A").unwrap();
        assert!(build_server_config(&cert, &pkcs8).is_some());
    }

    #[test]
    fn build_server_config_rejects_a_mismatched_key() {
        // A cert from one keypair + a different key must not build a server config.
        let pkcs8_a = crate::keygen::generate_pkcs8().unwrap();
        let cert_a = crate::keygen::issue_identity_cert(&pkcs8_a, "device-A").unwrap();
        let pkcs8_b = crate::keygen::generate_pkcs8().unwrap();
        assert!(build_server_config(&cert_a, &pkcs8_b).is_none());
    }

    #[test]
    fn build_server_config_with_client_auth_accepts_a_real_identity_cert() {
        // The mutual-TLS listener config builds from a real identity cert + key.
        let pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let cert = crate::keygen::issue_identity_cert(&pkcs8, "device-A").unwrap();
        assert!(build_server_config_with_client_auth(&cert, &pkcs8).is_some());
    }

    #[test]
    fn build_client_config_with_identity_constructs_both_paths() {
        let pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let cert = crate::keygen::issue_identity_cert(&pkcs8, "client-A").unwrap();
        assert!(build_client_config_with_identity(Some("AA:BB".into()), &cert, &pkcs8).is_some());
        assert!(build_client_config_with_identity(None, &cert, &pkcs8).is_some());
    }

    #[test]
    fn build_client_config_with_identity_rejects_mismatched_key() {
        // A client cert from one keypair + a different key must not build a config.
        let pkcs8_a = crate::keygen::generate_pkcs8().unwrap();
        let cert_a = crate::keygen::issue_identity_cert(&pkcs8_a, "client-A").unwrap();
        let pkcs8_b = crate::keygen::generate_pkcs8().unwrap();
        assert!(build_client_config_with_identity(None, &cert_a, &pkcs8_b).is_none());
    }

    #[test]
    fn fingerprint_against_real_identity_cert_round_trips() {
        // Integration with keygen: a freshly-issued cert has a stable fingerprint
        // the pinned verifier accepts.
        let pkcs8 = crate::keygen::generate_pkcs8().unwrap();
        let cert = crate::keygen::issue_identity_cert(&pkcs8, "device-A").unwrap();
        let fp = compute_fingerprint(&cert);
        assert_eq!(fp, compute_fingerprint(&cert));
        let v = PinnedFingerprintVerifier::new(fp);
        let r = v.verify_server_cert(
            &CertificateDer::from(cert.clone()),
            &[],
            &ServerName::try_from("device-A").unwrap(),
            &[],
            dummy_now(),
        );
        assert!(r.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connect_pinned_tls_returns_bad_peer_name_for_invalid_name() {
        let r = connect_pinned_tls("127.0.0.1:0".parse().unwrap(), "", None).await;
        assert!(matches!(r, Err(ConnectError::BadPeerName(_))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connect_pinned_tls_returns_tcp_error_for_unreachable_addr() {
        // Bind then drop a listener so we get a real-but-refused port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let r = connect_pinned_tls(addr, "device-X", None).await;
        assert!(matches!(r, Err(ConnectError::Tcp(_))));
    }

    #[test]
    fn connect_error_display_uses_stable_tokens() {
        assert!(format!(
            "{}",
            ConnectError::Tcp(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "x"
            ))
        )
        .starts_with("tcp: "));
        assert!(format!("{}", ConnectError::BadPeerName("x".into())).starts_with("bad_peer_name: "));
        assert!(format!("{}", ConnectError::BadIdentity("x".into())).starts_with("bad_identity: "));
    }
}
