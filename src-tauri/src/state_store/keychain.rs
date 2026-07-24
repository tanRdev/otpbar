use keyring::Entry;

use crate::{
    domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
    ports::SecretStore,
};

/// macOS Keychain-backed application-readable binary secret storage.
pub struct KeychainSecretStore;

impl SecretStore for KeychainSecretStore {
    fn read_secret(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
        map_read_result(state_entry(key)?.get_secret())
    }

    fn write_secret(&mut self, key: &str, value: &[u8]) -> Result<(), ErrorEnvelope> {
        state_entry(key)?
            .set_secret(value)
            .map_err(|error| storage_error(error.to_string()))
    }

    fn delete_secret(&mut self, key: &str) -> Result<(), ErrorEnvelope> {
        let entry = state_entry(key)?;
        let delete = entry.delete_credential();
        let read_back = entry.get_secret();
        verify_delete_results(delete, read_back)
    }
}

fn verify_delete_results(
    delete: Result<(), keyring::Error>,
    read_back: Result<Vec<u8>, keyring::Error>,
) -> Result<(), ErrorEnvelope> {
    match delete {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(error) => return Err(storage_error(error.to_string())),
    }
    match read_back {
        Err(keyring::Error::NoEntry) => Ok(()),
        Ok(_) => Err(storage_error(
            "secret remained after requested deletion".to_owned(),
        )),
        Err(error) => Err(storage_error(error.to_string())),
    }
}

fn map_read_result(
    result: Result<Vec<u8>, keyring::Error>,
) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(storage_error(error.to_string())),
    }
}

fn state_entry(key: &str) -> Result<Entry, ErrorEnvelope> {
    Entry::new("otpbar", key).map_err(|error| storage_error(error.to_string()))
}

fn storage_error(detail: String) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorCode::StorageUnavailable,
        UserMessage::LocalDataUnavailable,
        true,
    )
    .with_internal_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::{map_read_result, verify_delete_results};

    #[test]
    fn missing_entry_is_not_an_error() {
        assert!(matches!(
            map_read_result(Err(keyring::Error::NoEntry)),
            Ok(None)
        ));
    }

    #[test]
    fn keychain_failures_map_to_safe_storage_errors() {
        let result = map_read_result(Err(keyring::Error::Invalid(
            "secret".to_owned(),
            "injected detail".to_owned(),
        )));

        let error = result.expect_err("Keychain error must fail");
        let rendered = format!("{error:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("injected detail"));
    }

    #[test]
    fn deletion_requires_missing_readback() {
        assert!(verify_delete_results(Ok(()), Err(keyring::Error::NoEntry)).is_ok());
        assert!(verify_delete_results(Ok(()), Ok(vec![1, 2, 3])).is_err());
        assert!(verify_delete_results(
            Ok(()),
            Err(keyring::Error::Invalid(
                "read".to_owned(),
                "failed".to_owned()
            ))
        )
        .is_err());
    }
}
