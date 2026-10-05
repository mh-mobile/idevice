// Jackson Coxson

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use plist::Dictionary;
use plist_macro::plist_to_xml_bytes;
use rsa::rand_core::OsRng;
use serde::de::Error;
use tracing::{debug, warn};

use crate::IdeviceError;

#[derive(Clone)]
pub struct RpPairingFile {
    pub e_private_key: SigningKey,
    pub e_public_key: VerifyingKey,
    pub identifier: String,
    pub alt_irk: Option<Vec<u8>>,
    /// The peer's long-term Ed25519 public key and its identifier, as it gave them when the
    /// pairing was made (pair-setup). With them, pair-verify checks that the peer is that one;
    /// without them (a file made before they were kept) it is not checked, as before.
    pub peer_public_key: Option<VerifyingKey>,
    pub peer_identifier: Option<String>,
}

impl RpPairingFile {
    /// Returns the Ed25519 public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.e_public_key.to_bytes().to_vec()
    }

    /// Returns the Ed25519 private key bytes (32 bytes).
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.e_private_key.to_bytes().to_vec()
    }

    /// Returns the identifier string.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the `alt_irk` bytes (16 bytes).
    pub fn alt_irk(&self) -> Option<&[u8]> {
        self.alt_irk.as_deref()
    }

    pub fn generate(sending_host: &str) -> Self {
        // Ed25519 private key (persistent signing key)
        let ed25519_private_key = SigningKey::generate(&mut OsRng);
        let ed25519_public_key = VerifyingKey::from(&ed25519_private_key);

        let identifier =
            uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_DNS, sending_host.as_bytes()).to_string();

        Self {
            e_private_key: ed25519_private_key,
            e_public_key: ed25519_public_key,
            identifier,
            alt_irk: None,
            peer_public_key: None,
            peer_identifier: None,
        }
    }

    pub(crate) fn recreate_signing_keys(&mut self) {
        let ed25519_private_key = SigningKey::generate(&mut OsRng);
        let ed25519_public_key = VerifyingKey::from(&ed25519_private_key);
        self.e_public_key = ed25519_public_key;
        self.e_private_key = ed25519_private_key;
        self.alt_irk = None;
        self.peer_public_key = None;
        self.peer_identifier = None;
    }

    /// Serialize to XML plist bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "public_key".into(),
            plist::Value::Data(self.e_public_key.to_bytes().to_vec()),
        );
        dict.insert(
            "private_key".into(),
            plist::Value::Data(self.e_private_key.to_bytes().to_vec()),
        );
        dict.insert(
            "identifier".into(),
            plist::Value::String(self.identifier.clone()),
        );
        if let Some(irk) = &self.alt_irk {
            dict.insert("alt_irk".into(), plist::Value::Data(irk.clone()));
        }
        if let Some(key) = &self.peer_public_key {
            dict.insert(
                "peer_public_key".into(),
                plist::Value::Data(key.to_bytes().to_vec()),
            );
        }
        if let Some(identifier) = &self.peer_identifier {
            dict.insert(
                "peer_identifier".into(),
                plist::Value::String(identifier.clone()),
            );
        }
        plist_to_xml_bytes(&dict)
    }

    /// Parse from plist bytes (XML or binary).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdeviceError> {
        let mut p: Dictionary = plist::from_bytes(bytes)?;
        debug!("Read dictionary for rppairingfile: {p:#?}");

        let public_key = match p
            .remove("public_key")
            .and_then(|x| x.into_data())
            .filter(|x| x.len() == 32)
            .and_then(|x| VerifyingKey::from_bytes(&x[..32].try_into().unwrap()).ok())
        {
            Some(p) => p,
            None => {
                warn!("plist did not contain valid public key bytes");
                return Err(IdeviceError::Plist(plist::Error::missing_field(
                    "public_key",
                )));
            }
        };

        let private_key = match p
            .remove("private_key")
            .and_then(|x| x.into_data())
            .filter(|x| x.len() == 32)
        {
            Some(p) => SigningKey::from_bytes(&p.try_into().unwrap()),
            None => {
                warn!("plist did not contain valid private key bytes");
                return Err(IdeviceError::Plist(plist::Error::missing_field(
                    "private_key",
                )));
            }
        };

        let identifier = match p.remove("identifier").and_then(|x| x.into_string()) {
            Some(i) => i,
            None => {
                warn!("plist did not contain identifier");
                return Err(IdeviceError::Plist(plist::Error::missing_field(
                    "identifier",
                )));
            }
        };

        let alt_irk = match p.remove("alt_irk").and_then(|x| x.into_data()) {
            Some(irk) => Some(irk),
            None => {
                warn!("plist did not contain alt_irk");
                None
            }
        };

        // Optional: files made before the peer's identity was kept don't have them.
        let peer_public_key = p
            .remove("peer_public_key")
            .and_then(|x| x.into_data())
            .and_then(|x| <[u8; 32]>::try_from(x.as_slice()).ok())
            .and_then(|x| VerifyingKey::from_bytes(&x).ok());
        let peer_identifier = p.remove("peer_identifier").and_then(|x| x.into_string());

        Ok(Self {
            e_private_key: private_key,
            e_public_key: public_key,
            identifier,
            alt_irk,
            peer_public_key,
            peer_identifier,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn write_to_file(&self, path: impl AsRef<Path>) -> Result<(), IdeviceError> {
        tokio::fs::write(path, self.to_bytes()).await?;
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn read_from_file(path: impl AsRef<Path>) -> Result<Self, IdeviceError> {
        let bytes = tokio::fs::read(path).await?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for RpPairingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpPairingFile")
            .field("e_public_key", &self.e_public_key)
            .field("identifier", &self.identifier)
            .field("alt_irk", &self.alt_irk)
            .field("peer_public_key", &self.peer_public_key)
            .field("peer_identifier", &self.peer_identifier)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_identity_is_kept_and_a_file_without_it_reads_as_before() {
        let mut file = RpPairingFile::generate("host");
        let earlier = RpPairingFile::from_bytes(&file.to_bytes()).unwrap();
        assert!(earlier.peer_public_key.is_none() && earlier.peer_identifier.is_none());

        let peer = VerifyingKey::from(&SigningKey::generate(&mut OsRng));
        file.peer_public_key = Some(peer);
        file.peer_identifier = Some("4FD73E5E-0000-4000-8000-000000000000".into());
        let read = RpPairingFile::from_bytes(&file.to_bytes()).unwrap();
        assert_eq!(read.peer_public_key, Some(peer));
        assert_eq!(read.peer_identifier, file.peer_identifier);
        assert_eq!(read.identifier, file.identifier);
    }
}
