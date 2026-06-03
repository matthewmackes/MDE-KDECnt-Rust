//! RSA-2048 keypair + self-signed identity-cert generation (host increment 3b).
//!
//! `mde-kdc-proto` deliberately ships NO RSA keygen — ring 0.17.x does not expose
//! a stable RSA generator. The host owns it here with the pure-Rust `rsa` crate
//! (one-shot, first-launch only); the hot sign/verify path stays on ring via
//! `mde_kdc_proto::crypto::PairingKeyPair`.
//!
//! Output of [`generate_pkcs8`] is PKCS#8 DER bytes — the same format
//! `PairingKeyPair::from_pkcs8` accepts. [`issue_identity_cert`] binds a
//! self-signed X.509 cert (CN = device id) to that same keypair, so the cert the
//! peer pins and the key the host signs handshakes with are one identity.
//!
//! ## When this fires
//!
//! Once per peer-identity lifetime. The [`PairingStore`](crate::pairing) calls
//! this on first launch when no identity key exists, persists the PKCS#8 to
//! `~/.config/mde/connect/`, and never calls keygen again unless the operator
//! rotates identity.

use rand::rngs::OsRng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;

/// RSA modulus size in bits. Matches upstream KDE Connect's 2048-bit identity —
/// lower would break stock-client interop; higher is wasteful for an identity key.
pub const RSA_MODULUS_BITS: usize = 2048;

/// Errors keygen may surface. Stable `Display` tokens for audit-log entries.
#[derive(Debug)]
pub enum KeygenError {
    /// `rsa::RsaPrivateKey::new` failed — practically only when the OS RNG is
    /// broken. Surfaced as an error (not `expect`) so callers choose panic vs retry.
    RsaGenFailed,
    /// PKCS#8 serialization failed — defensive; would imply the `rsa` crate
    /// produced an unserializable key.
    Pkcs8EncodeFailed,
    /// rcgen-based X.509 cert issuance failed; wraps rcgen's own error rendering.
    CertIssueFailed(String),
}

impl std::fmt::Display for KeygenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeygenError::RsaGenFailed => write!(f, "rsa_gen_failed"),
            KeygenError::Pkcs8EncodeFailed => write!(f, "pkcs8_encode_failed"),
            KeygenError::CertIssueFailed(msg) => write!(f, "cert_issue_failed: {msg}"),
        }
    }
}

impl std::error::Error for KeygenError {}

/// Generate a fresh RSA-2048 keypair and return its PKCS#8 DER encoding. Feed the
/// bytes into [`PairingKeyPair::from_pkcs8`](mde_kdc_proto::crypto::PairingKeyPair::from_pkcs8)
/// to get a signable handle backed by ring.
pub fn generate_pkcs8() -> Result<Vec<u8>, KeygenError> {
    let mut rng = OsRng;
    let key =
        RsaPrivateKey::new(&mut rng, RSA_MODULUS_BITS).map_err(|_| KeygenError::RsaGenFailed)?;
    let pkcs8 = key
        .to_pkcs8_der()
        .map_err(|_| KeygenError::Pkcs8EncodeFailed)?;
    Ok(pkcs8.as_bytes().to_vec())
}

/// Issue a self-signed X.509 cert from an existing PKCS#8 RSA keypair. CN =
/// `device_id`; the SHA-256 fingerprint of this cert is the stable identity peers
/// pin in their pairing store. Self-signed + long-lived (100 years) — KDE
/// Connect's model is "the cert IS the identity"; trust is established by
/// fingerprint pinning at first pair, not a CA chain. Returns the cert as DER.
///
/// rcgen 0.13 re-creates the keypair from our PKCS#8 (via a PEM round-trip, the
/// more version-stable path), so the cert binds to the same RSA-2048 keypair the
/// handshake signs with.
pub fn issue_identity_cert(pkcs8_der: &[u8], device_id: &str) -> Result<Vec<u8>, KeygenError> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256};

    let pkcs8_pem = {
        use pkcs8::der::pem::LineEnding;
        use pkcs8::DecodePrivateKey;
        let parsed = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| KeygenError::CertIssueFailed(format!("decode pkcs8: {e}")))?;
        pkcs8::EncodePrivateKey::to_pkcs8_pem(&parsed, LineEnding::LF)
            .map_err(|e| KeygenError::CertIssueFailed(format!("re-pem pkcs8: {e}")))?
            .to_string()
    };
    let key_pair = KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8_pem, &PKCS_RSA_SHA256)
        .map_err(|e| KeygenError::CertIssueFailed(format!("rcgen keypair: {e}")))?;

    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_id.to_string());
        dn
    };
    // 100-year validity — the cert is long-lived; rotation is an operator action,
    // not expiry.
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2124, 1, 1);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| KeygenError::CertIssueFailed(format!("rcgen sign: {e}")))?;

    Ok(cert.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mde_kdc_proto::crypto::{verify_signature, PairingKeyPair};
    use rsa::pkcs8::DecodePrivateKey;

    #[test]
    fn generate_pkcs8_returns_loadable_keypair() {
        // Round-trip: generate -> load into ring via PairingKeyPair::from_pkcs8 ->
        // sign -> verify against a public key derived from the same private. The
        // bridge between the rsa crate (keygen) and ring (sign/verify).
        let pkcs8 = generate_pkcs8().expect("keygen succeeds");
        let kp = PairingKeyPair::from_pkcs8(&pkcs8).expect("ring accepts our PKCS#8");
        let signature = kp.sign(b"hello").expect("sign succeeds");
        assert!(!signature.is_empty());

        let private = RsaPrivateKey::from_pkcs8_der(&pkcs8).unwrap();
        let public = private.to_public_key();
        let pub_der = rsa::pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&public)
            .expect("public key to PKCS#1 DER");

        verify_signature(pub_der.as_bytes(), b"hello", &signature)
            .expect("signature verifies against derived public key");
    }

    #[test]
    fn generate_pkcs8_returns_nontrivial_bytes() {
        let pkcs8 = generate_pkcs8().unwrap();
        assert!(
            pkcs8.len() > 1000,
            "PKCS#8 DER ~1200 bytes; got {}",
            pkcs8.len()
        );
        assert!(
            pkcs8.len() < 1500,
            "PKCS#8 DER ~1200 bytes; got {}",
            pkcs8.len()
        );
    }

    #[test]
    fn two_consecutive_keygen_calls_produce_different_keys() {
        assert_ne!(
            generate_pkcs8().unwrap(),
            generate_pkcs8().unwrap(),
            "RNG must not repeat across consecutive calls"
        );
    }

    #[test]
    fn keygen_error_display_is_machine_token() {
        assert_eq!(format!("{}", KeygenError::RsaGenFailed), "rsa_gen_failed");
        assert_eq!(
            format!("{}", KeygenError::Pkcs8EncodeFailed),
            "pkcs8_encode_failed"
        );
        assert!(format!("{}", KeygenError::CertIssueFailed("nope".into()))
            .starts_with("cert_issue_failed: "));
    }

    #[test]
    fn issue_identity_cert_returns_nontrivial_der() {
        let pkcs8 = generate_pkcs8().unwrap();
        let cert_der = issue_identity_cert(&pkcs8, "device-abc-123").unwrap();
        assert!(
            cert_der.len() > 500 && cert_der.len() < 2000,
            "cert DER unexpectedly sized: {}",
            cert_der.len()
        );
    }

    #[test]
    fn issue_identity_cert_embeds_the_device_id_cn() {
        let pkcs8 = generate_pkcs8().unwrap();
        let cert_der = issue_identity_cert(&pkcs8, "device-abc-123").unwrap();
        assert!(
            cert_der.windows(14).any(|w| w == b"device-abc-123"),
            "device-id CN not present in cert DER"
        );
    }

    #[test]
    fn issue_identity_cert_different_device_ids_produce_different_certs() {
        let pkcs8 = generate_pkcs8().unwrap();
        let c1 = issue_identity_cert(&pkcs8, "device-A").unwrap();
        let c2 = issue_identity_cert(&pkcs8, "device-B").unwrap();
        assert_ne!(c1, c2, "different device-ids must produce different certs");
        assert!(c1.windows(8).any(|w| w == b"device-A"));
        assert!(c2.windows(8).any(|w| w == b"device-B"));
    }

    #[test]
    fn issue_identity_cert_rejects_invalid_pkcs8() {
        let err = issue_identity_cert(b"not a pkcs8 blob", "device-X")
            .expect_err("garbage PKCS#8 must reject");
        assert!(matches!(err, KeygenError::CertIssueFailed(_)));
    }
}
