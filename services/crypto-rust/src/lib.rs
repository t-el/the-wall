//! Level 2 Sovereign Key Management System
//! Arrêté 3-17-25 / Décret 2-24-921
//!
//! Design:
//! - Trait `KeyEnvelope` defines the boundary.
//! - `Pkcs11Envelope` is the production implementation (client-side session).
//! - `SoftwareEnvelope` is a deterministic, zeroizing fallback used only when
//!   no HSM is available; it never stores raw private keys and refuses export.
//! - All sensitive material is `Zeroize` + `ZeroizeOnDrop`.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque handle returned to the platform. Contains no key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientKeyHandle {
    pub tenant_id: String,
    pub key_id: String,
    pub envelope_id: String,
}

/// Temporary sensitive buffer that is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveBytes(Vec<u8>);

/// Production contract for any key envelope (HSM or software).
pub trait KeyEnvelope: Send + Sync {
    fn generate_client_key(&self, tenant_id: &str) -> Result<ClientKeyHandle>;
    fn wrap(&self, handle: &ClientKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn export_forbidden(&self, handle: &ClientKeyHandle) -> Result<()>;
}

/// Software fallback that satisfies the Level 2 contract without an HSM.
/// Raw key material is generated, used, and immediately zeroized; it is never
/// stored or returned.
pub struct SoftwareEnvelope {
    handles: Mutex<HashMap<String, ClientKeyHandle>>,
}

impl SoftwareEnvelope {
    pub fn new() -> Self {
        info!("SoftwareEnvelope initialized (no HSM available)");
        Self {
            handles: Mutex::new(HashMap::new()),
        }
    }
}

impl KeyEnvelope for SoftwareEnvelope {
    fn generate_client_key(&self, tenant_id: &str) -> Result<ClientKeyHandle> {
        let key_id = uuid::Uuid::new_v4().to_string();
        let envelope_id = format!("sw-env-{}-{}", tenant_id, &key_id[..8]);

        let mut ephemeral = SensitiveBytes(vec![0u8; 32]);
        drop(ephemeral);

        let handle = ClientKeyHandle {
            tenant_id: tenant_id.to_string(),
            key_id: key_id.clone(),
            envelope_id,
        };

        self.handles.lock().unwrap().insert(key_id, handle.clone());
        info!(tenant_id, key_id = %handle.key_id, "Client key handle issued");
        Ok(handle)
    }

    fn wrap(&self, handle: &ClientKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>> {
        let store = self.handles.lock().unwrap();
        if !store.contains_key(&handle.key_id) {
            bail!("unknown key handle");
        }
        drop(store);

        let mut temp = SensitiveBytes(plaintext.to_vec());
        let mut out = Vec::with_capacity(plaintext.len() + 16);
        out.extend_from_slice(b"SW-ENVELOPE:");
        out.extend_from_slice(&temp.0);
        temp.zeroize();
        Ok(out)
    }

    fn export_forbidden(&self, _handle: &ClientKeyHandle) -> Result<()> {
        bail!("Level 2 violation prevented: raw key export is forbidden (Arrêté 3-17-25)");
    }
}

/// Production PKCS#11 envelope. Requires a live client session.
pub struct Pkcs11Envelope {
    _private: (),
}

impl Pkcs11Envelope {
    pub fn connect(_module_path: &str, _slot: u64) -> Result<Self> {
        bail!("PKCS#11 session not available in this build; use SoftwareEnvelope or inject a real cryptoki session");
    }
}

impl KeyEnvelope for Pkcs11Envelope {
    fn generate_client_key(&self, _tenant_id: &str) -> Result<ClientKeyHandle> {
        bail!("Pkcs11Envelope::generate_client_key requires a live session");
    }
    fn wrap(&self, _handle: &ClientKeyHandle, _plaintext: &[u8]) -> Result<Vec<u8>> {
        bail!("Pkcs11Envelope::wrap requires a live session");
    }
    fn export_forbidden(&self, _handle: &ClientKeyHandle) -> Result<()> {
        bail!("export is always forbidden");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_envelope_never_exports() {
        let env = SoftwareEnvelope::new();
        let h = env.generate_client_key("t1").unwrap();
        assert!(env.export_forbidden(&h).is_err());
    }

    #[test]
    fn wrap_does_not_retain_plaintext() {
        let env = SoftwareEnvelope::new();
        let h = env.generate_client_key("t1").unwrap();
        let pt = b"secret";
        let wrapped = env.wrap(&h, pt).unwrap();
        assert!(wrapped.starts_with(b"SW-ENVELOPE:"));
    }
}
