//! Versioned Google Authorization credentials persisted as one Keychain value.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{clock::Timestamp, ports::SecretStore};

const CREDENTIAL_KEY: &str = "authorization.google.credentials.v1";
const CREDENTIAL_VERSION: u8 = 1;

/// Stable, secret-free credential persistence failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// Keychain access failed or deletion could not be verified.
    StoreUnavailable,
    /// Stored bytes were malformed, unsupported, or incomplete.
    InvalidStoredCredentials,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StoreUnavailable => "Authorization credentials are temporarily unavailable.",
            Self::InvalidStoredCredentials => "Stored Authorization credentials are invalid.",
        })
    }
}

impl std::error::Error for CredentialError {}

impl CredentialError {
    /// Maps persistence failures into the pure Authorization state machine.
    pub const fn authorization_failure(self) -> super::core::AuthorizationFailure {
        match self {
            Self::StoreUnavailable => super::core::AuthorizationFailure::CredentialStoreUnavailable,
            Self::InvalidStoredCredentials => super::core::AuthorizationFailure::RefreshRequired,
        }
    }
}

/// Access and refresh credentials plus their verified Gmail Mailbox Identity.
///
/// Formatting redacts every field, including Mailbox Identity.
pub struct CredentialBundle {
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    expires_at: Timestamp,
    mailbox_identity: Zeroizing<String>,
}

impl CredentialBundle {
    /// Constructs one complete credential bundle after a trusted provider exchange.
    pub fn new(
        access_token: String,
        refresh_token: String,
        expires_at: Timestamp,
        mailbox_identity: String,
    ) -> Result<Self, CredentialError> {
        if access_token.is_empty() || refresh_token.is_empty() || mailbox_identity.is_empty() {
            return Err(CredentialError::InvalidStoredCredentials);
        }
        Ok(Self {
            access_token: Zeroizing::new(access_token),
            refresh_token: Zeroizing::new(refresh_token),
            expires_at,
            mailbox_identity: Zeroizing::new(mailbox_identity),
        })
    }

    /// Returns the access credential only for an authenticated request.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the refresh credential only for a refresh request.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// Returns the access credential expiry.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns the verified Gmail Mailbox Identity for in-process display/use.
    pub fn mailbox_identity(&self) -> &str {
        &self.mailbox_identity
    }
}

impl fmt::Debug for CredentialBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBundle")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("mailbox_identity", &"[redacted]")
            .finish()
    }
}

#[derive(Serialize)]
struct PersistedCredential<'a> {
    version: u8,
    access_token: &'a str,
    refresh_token: &'a str,
    expires_at_millis: i64,
    mailbox_identity: &'a str,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct RestoredCredential {
    version: u8,
    access_token: String,
    refresh_token: String,
    expires_at_millis: i64,
    mailbox_identity: String,
}

/// Credential persistence over the production macOS Keychain `SecretStore`.
pub struct CredentialRepository<S> {
    store: S,
}

impl<S: SecretStore> CredentialRepository<S> {
    /// Creates a repository over one application-readable Keychain boundary.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Restores the complete credential bundle, or `None` after disconnect.
    pub fn restore(&self) -> Result<Option<CredentialBundle>, CredentialError> {
        let Some(bytes) = self
            .store
            .read_secret(CREDENTIAL_KEY)
            .map_err(|_| CredentialError::StoreUnavailable)?
        else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        let mut restored: RestoredCredential = serde_json::from_slice(&bytes)
            .map_err(|_| CredentialError::InvalidStoredCredentials)?;
        if restored.version != CREDENTIAL_VERSION {
            return Err(CredentialError::InvalidStoredCredentials);
        }
        CredentialBundle::new(
            std::mem::take(&mut restored.access_token),
            std::mem::take(&mut restored.refresh_token),
            Timestamp::from_unix_millis(restored.expires_at_millis),
            std::mem::take(&mut restored.mailbox_identity),
        )
        .map(Some)
    }

    /// Persists all credentials and Mailbox Identity in one Keychain write.
    pub fn persist(&mut self, credentials: &CredentialBundle) -> Result<(), CredentialError> {
        let persisted = PersistedCredential {
            version: CREDENTIAL_VERSION,
            access_token: credentials.access_token(),
            refresh_token: credentials.refresh_token(),
            expires_at_millis: credentials.expires_at().unix_millis(),
            mailbox_identity: credentials.mailbox_identity(),
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&persisted)
                .map_err(|_| CredentialError::InvalidStoredCredentials)?,
        );
        self.store
            .write_secret(CREDENTIAL_KEY, &bytes)
            .map_err(|_| CredentialError::StoreUnavailable)
    }

    /// Removes the complete bundle. Missing credentials are already disconnected.
    pub fn disconnect(&mut self) -> Result<(), CredentialError> {
        self.store
            .delete_secret(CREDENTIAL_KEY)
            .map_err(|_| CredentialError::StoreUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
        ports::SecretStore,
    };

    use super::{CredentialBundle, CredentialError, CredentialRepository};
    use crate::clock::Timestamp;

    #[derive(Default)]
    struct FakeSecretStore {
        values: BTreeMap<String, Vec<u8>>,
        fail_reads: bool,
        fail_writes: bool,
        fail_deletes: bool,
    }

    impl SecretStore for FakeSecretStore {
        fn read_secret(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
            if self.fail_reads {
                return Err(storage_error());
            }
            Ok(self.values.get(key).cloned())
        }

        fn write_secret(&mut self, key: &str, value: &[u8]) -> Result<(), ErrorEnvelope> {
            if self.fail_writes {
                return Err(storage_error());
            }
            self.values.insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete_secret(&mut self, key: &str) -> Result<(), ErrorEnvelope> {
            if self.fail_deletes {
                return Err(storage_error());
            }
            self.values.remove(key);
            Ok(())
        }
    }

    fn storage_error() -> ErrorEnvelope {
        ErrorEnvelope::new(
            ErrorCode::StorageUnavailable,
            UserMessage::LocalDataUnavailable,
            true,
        )
    }

    #[test]
    fn keychain_read_write_and_delete_failures_are_typed_and_redacted() {
        let read = CredentialRepository::new(FakeSecretStore {
            fail_reads: true,
            ..FakeSecretStore::default()
        });
        assert!(matches!(
            read.restore(),
            Err(CredentialError::StoreUnavailable)
        ));

        let mut write = CredentialRepository::new(FakeSecretStore {
            fail_writes: true,
            ..FakeSecretStore::default()
        });
        assert_eq!(
            write.persist(
                &CredentialBundle::new(
                    "access-secret".to_owned(),
                    "refresh-secret".to_owned(),
                    Timestamp::from_unix_millis(3_600_000),
                    "person@example.com".to_owned(),
                )
                .unwrap()
            ),
            Err(CredentialError::StoreUnavailable)
        );

        let mut delete = CredentialRepository::new(FakeSecretStore {
            fail_deletes: true,
            ..FakeSecretStore::default()
        });
        assert_eq!(delete.disconnect(), Err(CredentialError::StoreUnavailable));

        for error in [
            read.restore().unwrap_err(),
            write
                .persist(
                    &CredentialBundle::new(
                        "access-secret".to_owned(),
                        "refresh-secret".to_owned(),
                        Timestamp::from_unix_millis(3_600_000),
                        "person@example.com".to_owned(),
                    )
                    .unwrap(),
                )
                .unwrap_err(),
            delete.disconnect().unwrap_err(),
        ] {
            let rendered = format!("{error:?}");
            assert!(!rendered.contains("access-secret"));
            assert!(!rendered.contains("refresh-secret"));
            assert!(!rendered.contains("person@example.com"));
        }
    }

    #[test]
    fn mailbox_identity_restores_and_disconnect_allows_clean_reauthorization() {
        let mut repository = CredentialRepository::new(FakeSecretStore::default());
        let first = CredentialBundle::new(
            "first-access".to_owned(),
            "first-refresh".to_owned(),
            Timestamp::from_unix_millis(3_600_000),
            "first@example.com".to_owned(),
        )
        .unwrap();
        repository.persist(&first).unwrap();

        let restored = repository.restore().unwrap().unwrap();
        assert_eq!(restored.mailbox_identity(), "first@example.com");
        assert_eq!(restored.refresh_token(), "first-refresh");

        repository.disconnect().unwrap();
        assert!(repository.restore().unwrap().is_none());

        let second = CredentialBundle::new(
            "second-access".to_owned(),
            "second-refresh".to_owned(),
            Timestamp::from_unix_millis(7_200_000),
            "second@example.com".to_owned(),
        )
        .unwrap();
        repository.persist(&second).unwrap();
        let restored = repository.restore().unwrap().unwrap();
        assert_eq!(restored.mailbox_identity(), "second@example.com");
        assert_eq!(restored.refresh_token(), "second-refresh");
        assert!(!format!("{restored:?}").contains("second@example.com"));
    }
}
