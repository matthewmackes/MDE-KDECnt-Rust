//! The on-disk pairing store at `~/.config/mde/connect/`.
//!
//! The protocol crate deliberately owns no filesystem and no RSA keygen, so the
//! host provides both here. [`PairingStore`]:
//!
//! - generates (once) and persists this host's RSA-2048 identity key as
//!   `identity.pkcs8` (PKCS#8 DER, mode 0600), generating it with the `rsa`
//!   crate — which the protocol crate can't — and signing with the protocol's
//!   ring-backed [`PairingKeyPair`];
//! - persists the trusted-peer records as `devices.toml` (atomic write);
//! - implements the protocol's [`mde_kdc_proto::crypto::KeyStore`], delegating
//!   ephemeral AES session keys to an in-memory [`RingKeyStore`] (only the
//!   long-lived device records ever touch disk — never raw session keys).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mde_kdc_proto::crypto::{KeyHandle, KeyStore, PairingKeyPair, RingKeyStore};
use serde::{Deserialize, Serialize};

use crate::error::HostError;

/// One trusted peer, as persisted in `devices.toml`. The peer's public key and
/// certificate fingerprint are added by the pairing handshake (a later
/// increment); this increment persists the identity + audit fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// The peer's `Announce.device_id`.
    pub device_id: String,
    /// The peer's last-seen friendly name (for the surface's device list).
    pub device_name: String,
    /// Unix-millisecond timestamp of when the peer was first paired (audit).
    pub paired_at_ms: i64,
    /// The peer's pinned TLS identity: the SHA-256 fingerprint of its self-signed
    /// cert ([`crate::tls::compute_fingerprint`]), recorded at first pair. Every
    /// later TLS handshake to this peer must present a cert with this fingerprint
    /// (the `PinnedFingerprintVerifier`); a mismatch is a key-change/MITM signal.
    /// `#[serde(default)]` so a `devices.toml` written before this field loads as
    /// an empty pin (which the transport treats as not-yet-pinned).
    #[serde(default)]
    pub fingerprint: String,
}

/// The `devices.toml` document root: a list of `[[device]]` tables.
#[derive(Debug, Default, Serialize, Deserialize)]
struct DeviceFile {
    #[serde(default)]
    device: Vec<DeviceRecord>,
}

/// The host pairing store: this host's identity keypair, the persisted trusted
/// peers, and an in-memory store of live AES session keys.
pub struct PairingStore {
    dir: PathBuf,
    keypair: PairingKeyPair,
    /// This host's RSA public key as PKCS#1 `RSAPublicKey` DER — the form
    /// [`mde_kdc_proto::crypto::verify_signature`] expects.
    public_key_der: Vec<u8>,
    devices: HashMap<String, DeviceRecord>,
    sessions: RingKeyStore,
}

impl PairingStore {
    /// The conventional store directory, `$XDG_CONFIG_HOME/mde/connect`
    /// (falling back to `$HOME/.config/mde/connect`).
    pub fn default_dir() -> Result<PathBuf, HostError> {
        // Per the XDG spec, an empty $XDG_CONFIG_HOME is treated as unset, so
        // filter the empty string out before it shadows the $HOME fallback (else
        // a set-but-empty var yields a relative `mde/connect` under the CWD).
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .ok_or(HostError::NoConfigDir)?;
        Ok(base.join("mde").join("connect"))
    }

    /// Open (or first-time create) the store under `dir`. Generates
    /// `identity.pkcs8` with the `rsa` crate if absent, else loads it through
    /// [`PairingKeyPair::from_pkcs8`]; reads `devices.toml`, tolerating a
    /// missing or garbage file by starting empty.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, HostError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        // The store dir holds the long-lived identity key; keep it owner-only.
        // Harmless to re-apply on every open (the key file is created 0600
        // regardless, so this is defense-in-depth on the containing dir).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

        let key_path = dir.join("identity.pkcs8");
        let pkcs8 = if key_path.exists() {
            std::fs::read(&key_path)?
        } else {
            let der = generate_pkcs8()?;
            write_private(&key_path, &der)?;
            der
        };
        let keypair = PairingKeyPair::from_pkcs8(&pkcs8)?;
        let public_key_der = public_key_pkcs1_from_pkcs8(&pkcs8)?;
        let devices = read_devices(&dir);

        Ok(Self {
            dir,
            keypair,
            public_key_der,
            devices,
            sessions: RingKeyStore::new(),
        })
    }

    /// This host's RSA public key (PKCS#1 `RSAPublicKey` DER), to advertise
    /// during pairing and to feed to `verify_signature`.
    #[must_use]
    pub fn public_key_der(&self) -> Vec<u8> {
        self.public_key_der.clone()
    }

    /// This host's identity private key as PKCS#8 DER. The LAN transport needs it
    /// to build its inbound TLS `ServerConfig` (it must present a cert + key) and
    /// to issue its self-signed identity cert. In-process only — same trust domain
    /// as the on-disk `identity.pkcs8` (0600) this returns a copy of; never sent on
    /// the wire or logged.
    #[must_use]
    pub fn identity_pkcs8(&self) -> &[u8] {
        self.keypair.pkcs8_bytes()
    }

    /// Sign a handshake challenge with this host's identity key
    /// (RSA-PKCS1-v1_5 / SHA-256).
    pub fn sign_challenge(&self, message: &[u8]) -> Result<Vec<u8>, HostError> {
        Ok(self.keypair.sign(message)?)
    }

    /// Whether `device_id` is a trusted, persisted peer (drives
    /// `PluginContext.paired`).
    #[must_use]
    pub fn is_paired(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }

    /// Look up a trusted peer's record.
    #[must_use]
    pub fn get(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices.get(device_id)
    }

    /// Every trusted peer, for enumeration — e.g. a host surfacing the paired-device
    /// roster (the `mde connect` daemon's `Devices()`). Iteration order is unspecified.
    #[must_use]
    pub fn records(&self) -> Vec<&DeviceRecord> {
        self.devices.values().collect()
    }

    /// Number of trusted peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the store has no trusted peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Trust a peer and persist the store (atomic write of `devices.toml`).
    pub fn pair(&mut self, record: DeviceRecord) -> Result<(), HostError> {
        self.devices.insert(record.device_id.clone(), record);
        self.persist()
    }

    /// Untrust a peer and persist the store. No-op for an unknown id.
    pub fn unpair(&mut self, device_id: &str) -> Result<(), HostError> {
        self.devices.remove(device_id);
        self.persist()
    }

    fn persist(&self) -> Result<(), HostError> {
        let file = DeviceFile {
            device: self.devices.values().cloned().collect(),
        };
        let text = toml::to_string_pretty(&file)?;
        let path = self.dir.join("devices.toml");
        let tmp = self.dir.join("devices.toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// The store fronts the protocol's session-key store so the wire layer can hold
/// it as `Box<dyn KeyStore>`. Only ephemeral session keys flow through here;
/// they live in memory and are zeroized on drop — never persisted.
impl KeyStore for PairingStore {
    fn session_key(&self, handle: KeyHandle) -> Option<Vec<u8>> {
        self.sessions.session_key(handle)
    }

    fn install_session_key(&self, raw_key: &[u8]) -> KeyHandle {
        self.sessions.install_session_key(raw_key)
    }

    fn forget(&self, handle: KeyHandle) {
        self.sessions.forget(handle);
    }
}

/// Generate a fresh RSA-2048 keypair and return its PKCS#8 DER. The protocol
/// crate ships no keygen (ring 0.17 has none), so the host uses the `rsa` crate.
fn generate_pkcs8() -> Result<Vec<u8>, HostError> {
    use rsa::pkcs8::EncodePrivateKey;
    let mut rng = rand::thread_rng();
    let key =
        rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|e| HostError::Keygen(e.to_string()))?;
    let der = key
        .to_pkcs8_der()
        .map_err(|e| HostError::Keygen(e.to_string()))?;
    Ok(der.as_bytes().to_vec())
}

/// Derive the PKCS#1 `RSAPublicKey` DER (what `verify_signature` wants) from a
/// PKCS#8 private key.
fn public_key_pkcs1_from_pkcs8(pkcs8: &[u8]) -> Result<Vec<u8>, HostError> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::DecodePrivateKey;
    let key =
        rsa::RsaPrivateKey::from_pkcs8_der(pkcs8).map_err(|e| HostError::Keygen(e.to_string()))?;
    let der = key
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|e| HostError::Keygen(e.to_string()))?;
    Ok(der.as_bytes().to_vec())
}

/// Create a private-key file at mode 0600, applied atomically *at creation* so
/// the key bytes are never momentarily group/world-readable (the mode-after-write
/// idiom leaves a 0644 window under the usual umask). `create_new` (O_CREAT |
/// O_EXCL) additionally refuses to follow a pre-planted symlink, so the key can't
/// be redirected outside the store dir — `open()` has already confirmed the path
/// does not exist, so the exclusivity is free.
fn write_private(path: &Path, der: &[u8]) -> Result<(), HostError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(der)?;
    Ok(())
}

/// Read `devices.toml` into a map; a missing or unparseable file yields an empty
/// store (never an error — the daemon must always start).
fn read_devices(dir: &Path) -> HashMap<String, DeviceRecord> {
    let Ok(text) = std::fs::read_to_string(dir.join("devices.toml")) else {
        return HashMap::new();
    };
    let file: DeviceFile = toml::from_str(&text).unwrap_or_default();
    file.device
        .into_iter()
        .map(|d| (d.device_id.clone(), d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mde_kdc_proto::crypto::verify_signature;

    fn rec(id: &str) -> DeviceRecord {
        DeviceRecord {
            device_id: id.into(),
            device_name: "Phone".into(),
            paired_at_ms: 1,
            fingerprint: "AB:CD:EF".into(),
        }
    }

    #[test]
    fn open_creates_then_reloads_identity_key() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!tmp.path().join("identity.pkcs8").exists());
        let s1 = PairingStore::open(tmp.path()).unwrap();
        assert!(tmp.path().join("identity.pkcs8").exists());
        let pub1 = s1.public_key_der();
        assert!(!pub1.is_empty());
        // Reopen loads the SAME persisted key (no regeneration).
        let s2 = PairingStore::open(tmp.path()).unwrap();
        assert_eq!(s2.public_key_der(), pub1);
    }

    #[test]
    fn identity_key_and_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("connect");
        PairingStore::open(&dir).unwrap();
        // The private identity key must be 0600 — and created that way, not
        // chmod'd after a 0644 write (no group/world-readable window).
        let key_mode = std::fs::metadata(dir.join("identity.pkcs8"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            key_mode, 0o600,
            "identity.pkcs8 must be 0600, got {key_mode:o}"
        );
        // The store dir holding it is owner-only too.
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "store dir must be 0700, got {dir_mode:o}");
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let s = PairingStore::open(tmp.path()).unwrap();
        let msg = b"handshake-challenge";
        let sig = s.sign_challenge(msg).unwrap();
        // End-to-end proof of the rsa-keygen -> ring-sign -> ring-verify interop.
        verify_signature(&s.public_key_der(), msg, &sig).unwrap();
    }

    #[test]
    fn pair_persists_across_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut s = PairingStore::open(tmp.path()).unwrap();
            s.pair(rec("dev-1")).unwrap();
            assert!(s.is_paired("dev-1"));
            assert_eq!(s.len(), 1);
        }
        let s2 = PairingStore::open(tmp.path()).unwrap();
        assert!(s2.is_paired("dev-1"));
        assert_eq!(s2.get("dev-1").unwrap().device_name, "Phone");
        // The pinned fingerprint round-trips through devices.toml.
        assert_eq!(s2.get("dev-1").unwrap().fingerprint, "AB:CD:EF");
    }

    #[test]
    fn devices_toml_without_fingerprint_loads_with_empty_pin() {
        // Back-compat: a devices.toml written before the fingerprint field (e.g. a
        // store from increment 1) must still load, with an empty (not-yet-pinned)
        // fingerprint rather than a deserialize error.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("devices.toml"),
            "[[device]]\ndevice_id = \"old-1\"\ndevice_name = \"Legacy\"\npaired_at_ms = 42\n",
        )
        .unwrap();
        let s = PairingStore::open(tmp.path()).unwrap();
        let rec = s.get("old-1").expect("legacy record loads");
        assert_eq!(rec.device_name, "Legacy");
        assert_eq!(rec.fingerprint, "", "missing fingerprint defaults to empty");
    }

    #[test]
    fn unpair_persists_removal() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut s = PairingStore::open(tmp.path()).unwrap();
            s.pair(rec("dev-1")).unwrap();
            s.unpair("dev-1").unwrap();
        }
        assert!(!PairingStore::open(tmp.path()).unwrap().is_paired("dev-1"));
    }

    #[test]
    fn records_enumerates_every_paired_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = PairingStore::open(tmp.path()).unwrap();
        s.pair(rec("dev-1")).unwrap();
        s.pair(rec("dev-2")).unwrap();
        let mut ids: Vec<&str> = s.records().iter().map(|d| d.device_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["dev-1", "dev-2"]);
        assert!(PairingStore::open(tmp.path()).unwrap().records().len() == 2);
    }

    #[test]
    fn garbage_devices_file_loads_empty() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("devices.toml"), "not valid toml { [[[").unwrap();
        let s = PairingStore::open(tmp.path()).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn session_keys_delegate_to_ring_store() {
        let tmp = tempfile::tempdir().unwrap();
        let s = PairingStore::open(tmp.path()).unwrap();
        let h = s.install_session_key(&[7_u8; 32]);
        assert_eq!(s.session_key(h).as_deref(), Some(&[7_u8; 32][..]));
        s.forget(h);
        assert!(s.session_key(h).is_none());
    }
}
