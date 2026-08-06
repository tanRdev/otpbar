use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ports::{RandomSource, SecretStore};

/// Keychain item name holding the application-readable state key.
pub const STATE_KEY_NAME: &str = "atomic-state-key-v1";
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
    #[serde(with = "base64_bytes")]
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
#[derive(Clone)]
pub struct StateKey(Zeroizing<[u8; KEY_LENGTH]>);

impl StateKey {
    /// Rebuilds a key from exactly 256 bits of caller-owned secret material.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        key_from_bytes(bytes)
    }
}

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
    /// First-run creation was attempted after a state key already existed.
    KeyAlreadyExists,
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
    #[serde(with = "base64_bytes")]
    ciphertext: Vec<u8>,
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Zeroizing::new(STANDARD.encode(bytes));
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let capacity = encoded
            .len()
            .checked_div(4)
            .and_then(|groups| groups.checked_mul(3))
            .and_then(|bytes| bytes.checked_add(3))
            .ok_or_else(|| serde::de::Error::custom("base64 value is too large"))?;
        let mut decoded = Zeroizing::new(vec![0; capacity]);
        let length = STANDARD
            .decode_slice(encoded.as_bytes(), decoded.as_mut_slice())
            .map_err(serde::de::Error::custom)?;
        decoded.truncate(length);
        Ok(std::mem::take(decoded.as_mut()))
    }
}

/// Loads an existing state key without creating or mutating Keychain state.
pub(super) fn load_existing_key(
    secrets: &impl SecretStore,
) -> Result<Option<StateKey>, CryptoError> {
    if let Some(stored) = secrets
        .read_secret(STATE_KEY_NAME)
        .map_err(|_| CryptoError::SecretUnavailable)?
    {
        let stored = Zeroizing::new(stored);
        return key_from_bytes(stored.as_ref()).map(Some);
    }
    Ok(None)
}

/// Creates the state key only for a caller-confirmed first run.
pub(super) fn create_first_run_key(
    secrets: &mut impl SecretStore,
    random: &mut impl RandomSource,
) -> Result<StateKey, CryptoError> {
    if load_existing_key(secrets)?.is_some() {
        return Err(CryptoError::KeyAlreadyExists);
    }
    let mut generated = Zeroizing::new([0_u8; KEY_LENGTH]);
    random
        .fill_bytes(generated.as_mut())
        .map_err(|_| CryptoError::RandomUnavailable)?;
    secrets
        .write_secret(STATE_KEY_NAME, generated.as_ref())
        .map_err(|_| CryptoError::SecretUnavailable)?;
    Ok(StateKey(generated))
}

pub(super) fn key_from_bytes(bytes: &[u8]) -> Result<StateKey, CryptoError> {
    let key: [u8; KEY_LENGTH] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidStoredKey)?;
    Ok(StateKey(Zeroizing::new(key)))
}

/// Derives a stable opaque identifier without persisting a raw legacy ID.
pub(super) fn keyed_digest(key: &StateKey, domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key.0.as_ref())
        .expect("AES-256 key is a valid HMAC-SHA-256 key");
    mac.update(domain);
    mac.update(value);
    mac.finalize().into_bytes().into()
}

/// Removes the state key and proves that the secret store no longer returns it.
///
/// The production Keychain adapter performs its own read-back verification too;
/// this second check keeps the recovery invariant true for every `SecretStore`.
pub(super) fn delete_state_key(secrets: &mut impl SecretStore) -> Result<(), CryptoError> {
    secrets
        .delete_secret(STATE_KEY_NAME)
        .map_err(|_| CryptoError::SecretUnavailable)?;
    if secrets
        .read_secret(STATE_KEY_NAME)
        .map_err(|_| CryptoError::SecretUnavailable)?
        .is_some()
    {
        return Err(CryptoError::KeyAlreadyExists);
    }
    Ok(())
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

    use super::{create_first_run_key, decrypt, encrypt, load_existing_key, CryptoError, Snapshot};

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
        let key = create_first_run_key(&mut secrets, &mut random).expect("key creation");
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
    fn base64_payload_roundtrips_and_rejects_malformed_input() {
        let snapshot = Snapshot::new(3, vec![0, 1, 2, 0xfe, 0xff]);
        let encoded = serde_json::to_vec(&snapshot).expect("serialize base64 payload");
        let decoded: Snapshot =
            serde_json::from_slice(&encoded).expect("deserialize base64 payload");
        assert!(decoded == snapshot);

        let malformed = br#"{"schema_version":1,"revision":3,"payload":"AQ=!"}"#;
        assert!(serde_json::from_slice::<Snapshot>(malformed).is_err());
    }

    #[test]
    fn versioned_metadata_and_nonce_are_bound_to_authentication() {
        let mut secrets = MemorySecrets::default();
        let mut random = SequenceRandom::new([vec![0x11; 32], vec![0x22; 12]]);
        let key = create_first_run_key(&mut secrets, &mut random).expect("key creation");
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

        for field in ["format_version", "algorithm", "key_identifier"] {
            let envelope = encrypt(&snapshot, &key, &mut SequenceRandom::new([vec![0x33; 12]]))
                .expect("encryption");
            let mut encoded = serde_json::to_value(envelope).expect("envelope JSON");
            encoded[field] = match field {
                "format_version" => serde_json::json!(99),
                "algorithm" => serde_json::json!("not-aes-gcm"),
                "key_identifier" => serde_json::json!("other-key"),
                _ => unreachable!(),
            };
            let changed = serde_json::from_value(encoded).expect("changed envelope");
            assert!(matches!(
                decrypt(&changed, &key),
                Err(CryptoError::UnsupportedFormat)
            ));
        }
    }

    #[test]
    fn existing_key_is_reused_and_invalid_key_length_is_never_replaced() {
        let mut existing = MemorySecrets {
            value: Some(vec![0x11; 32]),
        };
        let mut nonce_only = SequenceRandom::new([vec![0x22; 12]]);
        let key = load_existing_key(&existing)
            .expect("load existing key")
            .expect("existing key");
        let snapshot = Snapshot::new(1, b"state".to_vec());
        assert!(encrypt(&snapshot, &key, &mut nonce_only).is_ok());
        assert_eq!(existing.value.as_deref(), Some(&[0x11; 32][..]));

        let invalid = MemorySecrets {
            value: Some(vec![0x44; 31]),
        };
        let mut unused_random = SequenceRandom::new(std::iter::empty::<Vec<u8>>());
        assert!(matches!(
            load_existing_key(&invalid),
            Err(CryptoError::InvalidStoredKey)
        ));
        assert_eq!(invalid.value.as_deref(), Some(&[0x44; 31][..]));

        assert!(matches!(
            create_first_run_key(&mut existing, &mut unused_random),
            Err(CryptoError::KeyAlreadyExists)
        ));
    }
}
