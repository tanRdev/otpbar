use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ports::{RandomSource, SecretStore};

const KEY_NAME: &str = "atomic-state-key-v1";
const KEY_IDENTIFIER: &str = "otpbar-local-state-v1";
const ALGORITHM: &str = "AES-256-GCM";
const ENVELOPE_FORMAT_VERSION: u32 = 1;
const ASSOCIATED_DATA_VERSION: u32 = 1;
const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

/// A versioned plaintext unit encrypted as one atomic consistency boundary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Snapshot {
    schema_version: u32,
    revision: u64,
    payload: Vec<u8>,
}

impl Snapshot {
    /// Creates a snapshot in the current storage schema.
    pub fn new(revision: u64, payload: Vec<u8>) -> Self {
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            revision,
            payload,
        }
    }

    /// Returns the caller-owned monotonic snapshot revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the opaque state document.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[cfg(test)]
    pub(super) fn with_schema(schema_version: u32, revision: u64, payload: Vec<u8>) -> Self {
        Self {
            schema_version,
            revision,
            payload,
        }
    }
}

/// An application-readable 256-bit state encryption key.
pub struct StateKey(Zeroizing<[u8; KEY_LENGTH]>);

/// Operating-system cryptographic random source used by production storage.
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill_bytes(
        &mut self,
        destination: &mut [u8],
    ) -> Result<(), crate::domain::error::ErrorEnvelope> {
        rand::rngs::OsRng
            .try_fill_bytes(destination)
            .map_err(|error| {
                crate::domain::error::ErrorEnvelope::new(
                    crate::domain::error::ErrorCode::StorageUnavailable,
                    crate::domain::error::UserMessage::LocalDataUnavailable,
                    true,
                )
                .with_internal_detail(error.to_string())
            })
    }
}

/// Stable classes of cryptographic state-store failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The secret store could not read or persist the key.
    SecretUnavailable,
    /// The stored key is not exactly 256 bits.
    InvalidStoredKey,
    /// Secure random bytes could not be obtained.
    RandomUnavailable,
    /// The plaintext or envelope could not be encoded.
    Encoding,
    /// The envelope uses a format this binary cannot safely read.
    UnsupportedFormat,
    /// Ciphertext authentication or plaintext validation failed.
    AuthenticationFailed,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct EncryptedEnvelope {
    format_version: u32,
    algorithm: String,
    key_identifier: String,
    associated_data_version: u32,
    nonce: [u8; NONCE_LENGTH],
    ciphertext: Vec<u8>,
}

/// Loads the state key or generates and persists a random 256-bit key.
pub fn load_or_create_key(
    secrets: &mut impl SecretStore,
    random: &mut impl RandomSource,
) -> Result<StateKey, CryptoError> {
    if let Some(stored) = secrets
        .read_secret(KEY_NAME)
        .map_err(|_| CryptoError::SecretUnavailable)?
    {
        let stored = Zeroizing::new(stored);
        return key_from_bytes(stored.as_ref());
    }

    let mut generated = Zeroizing::new([0_u8; KEY_LENGTH]);
    random
        .fill_bytes(generated.as_mut())
        .map_err(|_| CryptoError::RandomUnavailable)?;
    secrets
        .write_secret(KEY_NAME, generated.as_ref())
        .map_err(|_| CryptoError::SecretUnavailable)?;
    Ok(StateKey(generated))
}

pub(super) fn key_from_bytes(bytes: &[u8]) -> Result<StateKey, CryptoError> {
    let key: [u8; KEY_LENGTH] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidStoredKey)?;
    Ok(StateKey(Zeroizing::new(key)))
}

pub(super) fn encrypt(
    snapshot: &Snapshot,
    key: &StateKey,
    random: &mut impl RandomSource,
) -> Result<EncryptedEnvelope, CryptoError> {
    let mut nonce = [0_u8; NONCE_LENGTH];
    random
        .fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomUnavailable)?;
    let plaintext =
        Zeroizing::new(serde_json::to_vec(snapshot).map_err(|_| CryptoError::Encoding)?);
    let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| CryptoError::Encoding)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: associated_data(),
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(EncryptedEnvelope {
        format_version: ENVELOPE_FORMAT_VERSION,
        algorithm: ALGORITHM.to_owned(),
        key_identifier: KEY_IDENTIFIER.to_owned(),
        associated_data_version: ASSOCIATED_DATA_VERSION,
        nonce,
        ciphertext,
    })
}

pub(super) fn decrypt(
    envelope: &EncryptedEnvelope,
    key: &StateKey,
) -> Result<Snapshot, CryptoError> {
    validate_envelope(envelope)?;
    let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| CryptoError::Encoding)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: associated_data(),
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    let snapshot: Snapshot = serde_json::from_slice(plaintext.as_ref())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(CryptoError::UnsupportedFormat);
    }
    Ok(snapshot)
}

pub(super) fn encode(envelope: &EncryptedEnvelope) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(envelope).map_err(|_| CryptoError::Encoding)
}

pub(super) fn decode(bytes: &[u8]) -> Result<EncryptedEnvelope, CryptoError> {
    serde_json::from_slice(bytes).map_err(|_| CryptoError::AuthenticationFailed)
}

fn validate_envelope(envelope: &EncryptedEnvelope) -> Result<(), CryptoError> {
    if envelope.format_version != ENVELOPE_FORMAT_VERSION
        || envelope.algorithm != ALGORITHM
        || envelope.key_identifier != KEY_IDENTIFIER
        || envelope.associated_data_version != ASSOCIATED_DATA_VERSION
    {
        return Err(CryptoError::UnsupportedFormat);
    }
    Ok(())
}

fn associated_data() -> &'static [u8] {
    b"otpbar|encrypted-envelope=1|algorithm=AES-256-GCM|key=otpbar-local-state-v1|aad=1"
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crate::{
        domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
        ports::{RandomSource, SecretStore},
    };

    use super::{decrypt, encrypt, load_or_create_key, CryptoError, Snapshot};

    #[derive(Default)]
    struct MemorySecrets {
        value: Option<Vec<u8>>,
    }

    impl SecretStore for MemorySecrets {
        fn read_secret(&self, _key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
            Ok(self.value.clone())
        }

        fn write_secret(&mut self, _key: &str, value: &[u8]) -> Result<(), ErrorEnvelope> {
            self.value = Some(value.to_vec());
            Ok(())
        }

        fn delete_secret(&mut self, _key: &str) -> Result<(), ErrorEnvelope> {
            self.value = None;
            Ok(())
        }
    }

    struct SequenceRandom {
        values: VecDeque<Vec<u8>>,
    }

    impl SequenceRandom {
        fn new(values: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                values: values.into_iter().collect(),
            }
        }
    }

    impl RandomSource for SequenceRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ErrorEnvelope> {
            let value = self.values.pop_front().ok_or_else(|| {
                ErrorEnvelope::new(
                    ErrorCode::StorageUnavailable,
                    UserMessage::LocalDataUnavailable,
                    true,
                )
            })?;
            destination.copy_from_slice(&value);
            Ok(())
        }
    }

    #[test]
    fn key_and_nonce_are_random_and_ciphertext_is_authenticated() {
        let mut secrets = MemorySecrets::default();
        let mut random = SequenceRandom::new([vec![0x11; 32], vec![0x22; 12], vec![0x33; 12]]);
        let key = load_or_create_key(&mut secrets, &mut random).expect("key creation");
        assert_eq!(secrets.value.as_deref(), Some(&[0x11; 32][..]));

        let snapshot = Snapshot::new(7, br#"{"history":["123456"]}"#.to_vec());
        let first = encrypt(&snapshot, &key, &mut random).expect("first encryption");
        let second = encrypt(&snapshot, &key, &mut random).expect("second encryption");

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert!(decrypt(&first, &key).expect("round trip") == snapshot);

        let mut tampered = first;
        tampered.ciphertext[0] ^= 1;
        assert!(decrypt(&tampered, &key).is_err());
    }

    #[test]
    fn versioned_metadata_and_nonce_are_bound_to_authentication() {
        let mut secrets = MemorySecrets::default();
        let mut random = SequenceRandom::new([vec![0x11; 32], vec![0x22; 12]]);
        let key = load_or_create_key(&mut secrets, &mut random).expect("key creation");
        let snapshot = Snapshot::new(7, b"secret".to_vec());
        let envelope = encrypt(&snapshot, &key, &mut random).expect("encryption");

        let mut wrong_nonce = envelope.clone();
        wrong_nonce.nonce[0] ^= 1;
        assert!(matches!(
            decrypt(&wrong_nonce, &key),
            Err(CryptoError::AuthenticationFailed)
        ));

        let mut future_metadata = envelope;
        future_metadata.associated_data_version += 1;
        assert!(matches!(
            decrypt(&future_metadata, &key),
            Err(CryptoError::UnsupportedFormat)
        ));
    }

    #[test]
    fn existing_key_is_reused_and_invalid_key_length_is_never_replaced() {
        let mut existing = MemorySecrets {
            value: Some(vec![0x11; 32]),
        };
        let mut nonce_only = SequenceRandom::new([vec![0x22; 12]]);
        let key = load_or_create_key(&mut existing, &mut nonce_only).expect("existing key");
        let snapshot = Snapshot::new(1, b"state".to_vec());
        assert!(encrypt(&snapshot, &key, &mut nonce_only).is_ok());
        assert_eq!(existing.value.as_deref(), Some(&[0x11; 32][..]));

        let mut invalid = MemorySecrets {
            value: Some(vec![0x44; 31]),
        };
        let mut unused_random = SequenceRandom::new(std::iter::empty::<Vec<u8>>());
        assert!(matches!(
            load_or_create_key(&mut invalid, &mut unused_random),
            Err(CryptoError::InvalidStoredKey)
        ));
        assert_eq!(invalid.value.as_deref(), Some(&[0x44; 31][..]));
    }
}
