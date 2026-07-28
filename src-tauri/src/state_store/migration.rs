//! Restart-safe import of the legacy plaintext History file.
//!
//! The migration marker contains only lifecycle metadata and a hash of the
//! encrypted file. It never copies legacy History or a snapshot revision.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::ports::RandomSource;

use super::crypto::keyed_digest;
use super::{
    AtomicStateStore, CommitOutcome, LoadedStartup, RecoveryReason, Snapshot, StartupOutcome,
    StateKey, StoreAccessError,
};

/// Legacy filename read only during the v1-to-v2 transition.
pub const LEGACY_HISTORY_FILE_NAME: &str = "code_history.json";
const MARKER_FORMAT_VERSION: u32 = 1;
const MIGRATION_MARKER_SUFFIX: &str = ".otpbar-migration-v1";
const LEGACY_RETENTION_MILLISECONDS: i64 = 7 * 24 * 60 * 60 * 1000;
const LEGACY_HISTORY_LIMIT: usize = 50;
const MAX_LEGACY_PLAINTEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_MARKER_BYTES: usize = 4096;

/// One validated legacy History record. This intentionally has no revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyCodeEntry {
    pub code: String,
    pub sender: String,
    pub provider: String,
    pub timestamp: i64,
    pub message_id: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct MigratedHistory {
    schema_version: u32,
    written_at: i64,
    history: Vec<MigratedHistoryEntry>,
    seen_messages: Vec<serde_json::Value>,
    effect_outbox: Vec<serde_json::Value>,
    settings: MigratedAcceptanceSettings,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct MigratedHistoryEntry {
    id: String,
    code: String,
    message_origin_display: String,
    provider: MigratedProvider,
    received_at: i64,
    source_message_digest: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct MigratedProvider {
    key: String,
    display: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct MigratedAcceptanceSettings {
    history_retention_days: u8,
    auto_copy_consent: String,
    auto_copy_global_enabled: bool,
    auto_copy_provider_overrides: std::collections::BTreeMap<String, bool>,
    notification_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MarkerPhase {
    Prepared,
    EncryptedVerified,
}

#[derive(Serialize, Deserialize)]
struct MigrationMarker {
    format_version: u32,
    phase: MarkerPhase,
    /// Stable cutoff/written-at used for every restart of this migration.
    migration_timestamp_ms: i64,
    /// Keyed digest of the exact legacy bytes selected for deletion.
    legacy_digest: String,
    /// Hash of ciphertext, never a hash of plaintext or a duplicated revision.
    ciphertext_sha256: Option<String>,
}

/// The only object permitted to remove a legacy plaintext file after migration.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlaintextMigration;

impl PlaintextMigration {
    /// Applies migration to a lock-owning startup result without exposing a
    /// live `AtomicStateStore` on any failure path.
    pub fn migrate_startup(
        &self,
        startup: StartupOutcome,
        key: &StateKey,
        random: &mut impl RandomSource,
        now_timestamp: i64,
    ) -> MigrationStartupOutcome {
        let (mut store, was_absent) = match startup {
            StartupOutcome::Absent(store) => (store, true),
            StartupOutcome::LoadedMustCancelEffects(loaded) => {
                (loaded.into_store_for_migration(), false)
            }
            StartupOutcome::RecoveryRequired(recovery) => {
                return MigrationStartupOutcome::Unchanged(StartupOutcome::RecoveryRequired(
                    recovery,
                ));
            }
        };
        let legacy_path = match legacy_path_for_store(&store) {
            Ok(path) => path,
            Err(error) => {
                return MigrationStartupOutcome::RecoveryRequired {
                    recovery: store.into_read_only_recovery(RecoveryReason::MigrationFailed),
                    error,
                }
            }
        };
        let has_artifacts = match has_artifacts(&legacy_path) {
            Ok(value) => value,
            Err(error) => {
                return MigrationStartupOutcome::RecoveryRequired {
                    recovery: store.into_read_only_recovery(RecoveryReason::MigrationFailed),
                    error,
                }
            }
        };
        if !has_artifacts {
            return if was_absent {
                MigrationStartupOutcome::Unchanged(StartupOutcome::Absent(store))
            } else {
                match store.load(key) {
                    Ok(Some(snapshot)) => {
                        MigrationStartupOutcome::Unchanged(StartupOutcome::LoadedMustCancelEffects(
                            store.into_loaded_startup(snapshot),
                        ))
                    }
                    Ok(None) => MigrationStartupOutcome::RecoveryRequired {
                        recovery: store.into_read_only_recovery(RecoveryReason::MigrationFailed),
                        error: MigrationError::EncryptedStateDoesNotMatchLegacy,
                    },
                    Err(error) => MigrationStartupOutcome::RecoveryRequired {
                        recovery: store.into_read_only_recovery(RecoveryReason::MigrationFailed),
                        error: map_store_error(error),
                    },
                }
            };
        }
        match self.migrate_or_resume(&legacy_path, &mut store, key, random, now_timestamp) {
            Ok(MigrationOutcome::NoLegacyPlaintext) if was_absent => {
                MigrationStartupOutcome::Unchanged(StartupOutcome::Absent(store))
            }
            Ok(_) => match store.load(key) {
                Ok(Some(snapshot)) => {
                    MigrationStartupOutcome::Migrated(store.into_loaded_startup(snapshot))
                }
                Ok(None) => MigrationStartupOutcome::RecoveryRequired {
                    recovery: store.into_read_only_recovery(RecoveryReason::MigrationFailed),
                    error: MigrationError::EncryptedStateDoesNotMatchLegacy,
                },
                Err(error) => MigrationStartupOutcome::RecoveryRequired {
                    recovery: store.into_read_only_recovery(RecoveryReason::MigrationFailed),
                    error: map_store_error(error),
                },
            },
            Err(error) => MigrationStartupOutcome::RecoveryRequired {
                recovery: store.into_read_only_recovery(RecoveryReason::MigrationFailed),
                error,
            },
        }
    }

    /// Migrates a validated plaintext History only after verified encrypted commit.
    ///
    /// `store` must be the lock-owning store obtained from the normal startup
    /// path. A recovery or pending-barrier store never exposes a usable load,
    /// so this method cannot bypass those safety states.
    fn migrate_or_resume(
        &self,
        legacy_path: &Path,
        store: &mut AtomicStateStore,
        key: &StateKey,
        random: &mut impl RandomSource,
        now_timestamp: i64,
    ) -> Result<MigrationOutcome, MigrationError> {
        let marker_path = marker_path(legacy_path)?;
        let mut marker = read_marker(&marker_path)?;
        let pending_path = pending_delete_path(legacy_path)?;
        if !path_exists(legacy_path)? && path_exists(&pending_path)? {
            let marker = marker.as_ref().ok_or(MigrationError::MarkerInvalid)?;
            verify_resumed_ciphertext(store, key, None, marker)?;
            verify_pending_and_unlink(&pending_path, key, marker)?;
            finish_marker_cleanup(legacy_path, &marker_path)?;
            return Ok(MigrationOutcome::CompletedAfterRestart);
        }
        let cutoff = marker
            .as_ref()
            .map_or(now_timestamp, |marker| marker.migration_timestamp_ms);
        let legacy_bytes = read_legacy_bytes(legacy_path)?;
        let legacy = legacy_bytes
            .as_deref()
            .map(|bytes| parse_legacy(bytes, cutoff))
            .transpose()?;

        match (legacy, marker.take()) {
            (None, None) => Ok(MigrationOutcome::NoLegacyPlaintext),
            (None, Some(marker)) if marker.phase == MarkerPhase::EncryptedVerified => {
                verify_resumed_ciphertext(store, key, None, &marker)?;
                finish_marker_cleanup(legacy_path, &marker_path)?;
                Ok(MigrationOutcome::CompletedAfterRestart)
            }
            (None, Some(_)) => Err(MigrationError::MissingPlaintextBeforeEncryptedCommit),
            (Some(entries), marker) => {
                let raw = legacy_bytes
                    .as_deref()
                    .ok_or(MigrationError::LegacyReadFailed)?;
                let raw_digest = legacy_digest(key, raw);
                let payload = canonical_payload(entries, key, cutoff)?;
                let mut marker = match marker {
                    Some(marker) if marker.legacy_digest == raw_digest => marker,
                    Some(_) => return Err(MigrationError::LegacyChangedBeforeDelete),
                    None => {
                        let marker = MigrationMarker {
                            format_version: MARKER_FORMAT_VERSION,
                            phase: MarkerPhase::Prepared,
                            migration_timestamp_ms: cutoff,
                            legacy_digest: raw_digest,
                            ciphertext_sha256: None,
                        };
                        write_marker(&marker_path, &marker)?;
                        marker
                    }
                };

                if marker.phase == MarkerPhase::EncryptedVerified {
                    verify_resumed_ciphertext(store, key, Some(&payload), &marker)?;
                } else {
                    let digest = verify_or_commit(store, key, random, &payload)?;
                    marker.phase = MarkerPhase::EncryptedVerified;
                    marker.ciphertext_sha256 = Some(digest);
                    write_marker(&marker_path, &marker)?;
                }

                verify_resumed_ciphertext(store, key, Some(&payload), &marker)?;
                move_verify_and_delete_plaintext(legacy_path, &pending_path, key, &marker)?;
                finish_marker_cleanup(legacy_path, &marker_path)?;
                Ok(MigrationOutcome::Migrated)
            }
        }
    }
}

/// Startup result after the migration gate. The error branch retains the
/// exclusive read-only owner, so a caller cannot start intake or overwrite
/// plaintext after an unsuccessful migration.
pub enum MigrationStartupOutcome {
    /// There was no migration work; preserve the ordinary startup state.
    Unchanged(StartupOutcome),
    /// Migration completed or its deletion phase resumed; effects still need
    /// the usual startup cancellation transition before activation.
    Migrated(LoadedStartup),
    /// Migration could not complete safely and intake must remain stopped.
    RecoveryRequired {
        recovery: super::ReadOnlyRecovery,
        error: MigrationError,
    },
}

/// Observable completion state for the migration startup gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// There was no v1 plaintext History to import.
    NoLegacyPlaintext,
    /// Plaintext was removed only after encrypted verification and parent sync.
    Migrated,
    /// A post-commit crash was completed without importing duplicate entries.
    CompletedAfterRestart,
}

/// Failure leaves intake stopped by the caller's startup gate and never deletes
/// plaintext before a verified encrypted snapshot exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationError {
    LegacyPathInvalid,
    LegacyReadFailed,
    LegacyUnsafeEntry,
    LegacyInvalid,
    MarkerReadFailed,
    MarkerInvalid,
    MarkerWriteFailed,
    MarkerDeleteFailed,
    ParentSyncFailed,
    MissingPlaintextBeforeEncryptedCommit,
    EncryptedStateDoesNotMatchLegacy,
    EncryptedCiphertextChanged,
    StoreRecovery(RecoveryReason),
    StoreCommitUncommitted,
    StoreCommitBlocked,
    PlaintextDeleteFailed,
    LegacyChangedBeforeDelete,
    LegacyRecreatedAfterDelete,
}

fn verify_or_commit(
    store: &mut AtomicStateStore,
    key: &StateKey,
    random: &mut impl RandomSource,
    payload: &[u8],
) -> Result<String, MigrationError> {
    match store.load(key) {
        Ok(Some(snapshot)) => {
            verify_payload(&snapshot, payload)?;
            migration_ciphertext_digest(store, key, Some(payload))
        }
        Ok(None) => match store.commit(Snapshot::new(1, payload.to_vec()), key, random) {
            CommitOutcome::Committed(_) => match store.load(key) {
                Ok(Some(snapshot)) => {
                    verify_payload(&snapshot, payload)?;
                    migration_ciphertext_digest(store, key, Some(payload))
                }
                Ok(None) => Err(MigrationError::EncryptedStateDoesNotMatchLegacy),
                Err(error) => Err(map_store_error(error)),
            },
            CommitOutcome::RecoveryRequired(reason) => Err(MigrationError::StoreRecovery(reason)),
            CommitOutcome::Uncommitted => Err(MigrationError::StoreCommitUncommitted),
            CommitOutcome::BarrierPending | CommitOutcome::Blocked | CommitOutcome::Rejected(_) => {
                Err(MigrationError::StoreCommitBlocked)
            }
        },
        Err(error) => Err(map_store_error(error)),
    }
}

fn verify_resumed_ciphertext(
    store: &mut AtomicStateStore,
    key: &StateKey,
    expected_payload: Option<&[u8]>,
    marker: &MigrationMarker,
) -> Result<(), MigrationError> {
    let expected = marker
        .ciphertext_sha256
        .as_deref()
        .ok_or(MigrationError::MarkerInvalid)?;
    if migration_ciphertext_digest(store, key, expected_payload)? != expected {
        return Err(MigrationError::EncryptedCiphertextChanged);
    }
    Ok(())
}

fn verify_payload(snapshot: &Snapshot, expected: &[u8]) -> Result<(), MigrationError> {
    if snapshot.revision() == 1 && snapshot.payload() == expected {
        Ok(())
    } else {
        Err(MigrationError::EncryptedStateDoesNotMatchLegacy)
    }
}

fn map_store_error(error: StoreAccessError) -> MigrationError {
    match error {
        StoreAccessError::BarrierPending => MigrationError::StoreCommitBlocked,
        StoreAccessError::RecoveryRequired(reason) => MigrationError::StoreRecovery(reason),
    }
}

fn canonical_payload(
    mut entries: Vec<LegacyCodeEntry>,
    key: &StateKey,
    now_timestamp: i64,
) -> Result<Vec<u8>, MigrationError> {
    for entry in &entries {
        if entry.code.is_empty()
            || entry.sender.is_empty()
            || entry.provider.is_empty()
            || entry.message_id.is_empty()
        {
            return Err(MigrationError::LegacyInvalid);
        }
    }
    entries.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    let history = entries
        .into_iter()
        .map(|entry| MigratedHistoryEntry {
            id: hex::encode(keyed_digest(
                key,
                b"otpbar|migration-history-id=1|",
                format!("{}|{}|{}", entry.message_id, entry.timestamp, entry.code).as_bytes(),
            )),
            code: entry.code,
            message_origin_display: entry.sender,
            provider: MigratedProvider {
                key: normalized_provider_key(&entry.provider),
                display: entry.provider,
            },
            received_at: entry.timestamp,
            source_message_digest: hex::encode(keyed_digest(
                key,
                b"otpbar|migration-source-message=1|",
                entry.message_id.as_bytes(),
            )),
        })
        .collect();
    serde_json::to_vec(&MigratedHistory {
        schema_version: 1,
        written_at: now_timestamp,
        history,
        seen_messages: vec![],
        effect_outbox: vec![],
        settings: MigratedAcceptanceSettings {
            history_retention_days: 7,
            auto_copy_consent: "unknown".to_owned(),
            auto_copy_global_enabled: false,
            auto_copy_provider_overrides: Default::default(),
            notification_enabled: false,
        },
    })
    .map_err(|_| MigrationError::LegacyInvalid)
}

fn normalized_provider_key(display: &str) -> String {
    display
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|character| character.is_ascii_alphanumeric())
        .collect()
}

#[cfg(test)]
fn read_legacy(
    path: &Path,
    now_timestamp: i64,
) -> Result<Option<Vec<LegacyCodeEntry>>, MigrationError> {
    read_legacy_bytes(path)?
        .map(|bytes| parse_legacy(&bytes, now_timestamp))
        .transpose()
}

fn read_legacy_bytes(path: &Path) -> Result<Option<Vec<u8>>, MigrationError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(MigrationError::LegacyUnsafeEntry)
        }
        Err(_) => return Err(MigrationError::LegacyReadFailed),
        Ok(_) => {}
    }
    Ok(Some(
        read_regular_limited(path, MAX_LEGACY_PLAINTEXT_BYTES)
            .map_err(|_| MigrationError::LegacyReadFailed)?,
    ))
}

fn parse_legacy(bytes: &[u8], now_timestamp: i64) -> Result<Vec<LegacyCodeEntry>, MigrationError> {
    let mut entries: Vec<LegacyCodeEntry> =
        serde_json::from_slice(bytes).map_err(|_| MigrationError::LegacyInvalid)?;
    let threshold = now_timestamp.saturating_sub(LEGACY_RETENTION_MILLISECONDS);
    for entry in &entries {
        if entry.code.is_empty()
            || entry.sender.is_empty()
            || entry.provider.is_empty()
            || entry.message_id.is_empty()
        {
            return Err(MigrationError::LegacyInvalid);
        }
    }
    entries.retain(|entry| entry.timestamp >= threshold && entry.timestamp <= now_timestamp);
    entries.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    entries.truncate(LEGACY_HISTORY_LIMIT);
    Ok(entries)
}

fn has_artifacts(legacy_path: &Path) -> Result<bool, MigrationError> {
    let marker_path = marker_path(legacy_path)?;
    let pending = pending_delete_path(legacy_path)?;
    Ok(path_exists(legacy_path)? || path_exists(&marker_path)? || path_exists(&pending)?)
}

fn path_exists(path: &Path) -> Result<bool, MigrationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(MigrationError::LegacyReadFailed),
    }
}

fn legacy_path_for_store(store: &AtomicStateStore) -> Result<PathBuf, MigrationError> {
    let parent = store
        .path()
        .parent()
        .ok_or(MigrationError::LegacyPathInvalid)?;
    Ok(parent.join(LEGACY_HISTORY_FILE_NAME))
}

fn marker_path(legacy_path: &Path) -> Result<PathBuf, MigrationError> {
    let parent = legacy_path
        .parent()
        .ok_or(MigrationError::LegacyPathInvalid)?;
    let file_name = legacy_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(MigrationError::LegacyPathInvalid)?;
    Ok(parent.join(format!(".{file_name}{MIGRATION_MARKER_SUFFIX}")))
}

fn pending_delete_path(legacy_path: &Path) -> Result<PathBuf, MigrationError> {
    let parent = legacy_path
        .parent()
        .ok_or(MigrationError::LegacyPathInvalid)?;
    let file_name = legacy_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(MigrationError::LegacyPathInvalid)?;
    Ok(parent.join(format!(".{file_name}.otpbar-pending-delete-v1")))
}

fn read_marker(path: &Path) -> Result<Option<MigrationMarker>, MigrationError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Ok(metadata) if !metadata.file_type().is_file() => Err(MigrationError::MarkerInvalid),
        Err(_) => Err(MigrationError::MarkerReadFailed),
        Ok(_) => {
            let bytes = read_regular_limited(path, MAX_MARKER_BYTES)
                .map_err(|_| MigrationError::MarkerReadFailed)?;
            let marker: MigrationMarker =
                serde_json::from_slice(&bytes).map_err(|_| MigrationError::MarkerInvalid)?;
            if marker.format_version != MARKER_FORMAT_VERSION
                || marker.legacy_digest.len() != 64
                || (marker.phase == MarkerPhase::Prepared && marker.ciphertext_sha256.is_some())
                || (marker.phase == MarkerPhase::EncryptedVerified
                    && marker
                        .ciphertext_sha256
                        .as_deref()
                        .is_none_or(str::is_empty))
            {
                return Err(MigrationError::MarkerInvalid);
            }
            Ok(Some(marker))
        }
    }
}

fn write_marker(path: &Path, marker: &MigrationMarker) -> Result<(), MigrationError> {
    let parent = path.parent().ok_or(MigrationError::LegacyPathInvalid)?;
    let bytes = serde_json::to_vec(marker).map_err(|_| MigrationError::MarkerWriteFailed)?;
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|_| MigrationError::MarkerWriteFailed)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| MigrationError::MarkerWriteFailed)?;
    fs::rename(&temp, path).map_err(|_| MigrationError::MarkerWriteFailed)?;
    sync_parent(path)
}

fn legacy_digest(key: &StateKey, bytes: &[u8]) -> String {
    hex::encode(keyed_digest(
        key,
        b"otpbar|migration-legacy-bytes=1|",
        bytes,
    ))
}

fn move_verify_and_delete_plaintext(
    legacy: &Path,
    pending: &Path,
    key: &StateKey,
    marker: &MigrationMarker,
) -> Result<(), MigrationError> {
    if path_exists(pending)? {
        return Err(MigrationError::LegacyChangedBeforeDelete);
    }
    fs::rename(legacy, pending).map_err(|_| MigrationError::PlaintextDeleteFailed)?;
    sync_parent(legacy)?;
    match verify_pending_and_unlink(pending, key, marker) {
        Ok(()) => Ok(()),
        Err(error) => {
            if !path_exists(legacy).unwrap_or(true) {
                let _ = fs::rename(pending, legacy);
                let _ = sync_parent(legacy);
            }
            Err(error)
        }
    }
}

fn verify_pending_and_unlink(
    pending: &Path,
    key: &StateKey,
    marker: &MigrationMarker,
) -> Result<(), MigrationError> {
    let bytes = read_regular_limited(pending, MAX_LEGACY_PLAINTEXT_BYTES)
        .map_err(|_| MigrationError::LegacyReadFailed)?;
    if legacy_digest(key, &bytes) != marker.legacy_digest {
        return Err(MigrationError::LegacyChangedBeforeDelete);
    }
    remove_regular(pending).map_err(|_| MigrationError::PlaintextDeleteFailed)?;
    sync_parent(pending)
}

fn remove_marker_and_sync(path: &Path) -> Result<(), MigrationError> {
    remove_regular(path).map_err(|_| MigrationError::MarkerDeleteFailed)?;
    sync_parent(path)
}

fn finish_marker_cleanup(legacy: &Path, marker: &Path) -> Result<(), MigrationError> {
    if path_exists(legacy)? {
        return Err(MigrationError::LegacyRecreatedAfterDelete);
    }
    remove_marker_and_sync(marker)
}

fn remove_regular(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(path),
        Ok(_) => Err(io::Error::other("migration path is not a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_parent(path: &Path) -> Result<(), MigrationError> {
    let parent = path.parent().ok_or(MigrationError::LegacyPathInvalid)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::ParentSyncFailed)
}

fn migration_ciphertext_digest(
    store: &mut AtomicStateStore,
    key: &StateKey,
    expected_payload: Option<&[u8]>,
) -> Result<String, MigrationError> {
    store
        .verified_migration_ciphertext_digest(key, expected_payload)
        .map_err(map_store_error)
}

fn read_regular_limited(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::other("migration input is not a regular file"));
    }
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    std::io::Read::by_ref(&mut file)
        .take((limit as u64) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "migration input exceeds limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
        ports::RandomSource,
        state_store::{Snapshot, StartupOutcome, StateStoreInitializer},
    };

    use super::{LegacyCodeEntry, MigrationError, MigrationStartupOutcome, PlaintextMigration};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "otpbar-migration-test-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    struct Random(VecDeque<Vec<u8>>);

    impl RandomSource for Random {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), ErrorEnvelope> {
            let bytes = self.0.pop_front().ok_or_else(|| {
                ErrorEnvelope::new(
                    ErrorCode::StorageUnavailable,
                    UserMessage::LocalDataUnavailable,
                    true,
                )
            })?;
            output.copy_from_slice(&bytes);
            Ok(())
        }
    }

    fn legacy_entry(timestamp: i64) -> LegacyCodeEntry {
        LegacyCodeEntry {
            code: "123456".to_owned(),
            sender: "Example".to_owned(),
            provider: "Example".to_owned(),
            timestamp,
            message_id: "message-1".to_owned(),
        }
    }

    fn state_path(directory: &TestDirectory) -> PathBuf {
        directory.0.join("state.json")
    }

    fn open_absent(
        path: PathBuf,
        key: &crate::state_store::StateKey,
    ) -> crate::state_store::AtomicStateStore {
        match StateStoreInitializer::open(path)
            .expect("lock")
            .initialize(key)
        {
            StartupOutcome::Absent(store) => store,
            outcome => panic!("expected absent store, got {outcome:?}"),
        }
    }

    fn key() -> crate::state_store::StateKey {
        // The private parser is intentionally avoided by production migration;
        // this test creates the normal first-run capability through a local fake.
        struct Secrets;
        impl crate::ports::SecretStore for Secrets {
            fn read_secret(&self, _: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
                Ok(None)
            }
            fn write_secret(&mut self, _: &str, _: &[u8]) -> Result<(), ErrorEnvelope> {
                Ok(())
            }
            fn delete_secret(&mut self, _: &str) -> Result<(), ErrorEnvelope> {
                Ok(())
            }
        }
        let path = std::env::temp_dir().join(format!(
            "otpbar-migration-key-{}",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("key directory");
        let mut secrets = Secrets;
        let mut random = Random(VecDeque::from([vec![7; 32]]));
        let capability = match StateStoreInitializer::open(path.join("state.json"))
            .expect("lock")
            .initialize_from_secrets(&secrets)
            .expect("lookup")
        {
            crate::state_store::SecretStartupOutcome::FirstRunNeedsKey(capability) => capability,
            _ => panic!("first run capability"),
        };
        let key = match capability
            .create(&mut secrets, &mut random)
            .expect("create")
        {
            crate::state_store::FirstRunCreationOutcome::KeyCreated { key, .. } => key,
            _ => panic!("key created"),
        };
        fs::remove_dir_all(path).expect("key directory removal");
        key
    }

    #[test]
    fn verified_migration_reads_back_then_removes_plaintext() {
        let directory = TestDirectory::new();
        let encrypted_path = state_path(&directory);
        let legacy_path = directory.0.join("code_history.json");
        let now = 1_700_000_000_000;
        fs::write(
            &legacy_path,
            serde_json::to_vec(&vec![legacy_entry(now)]).unwrap(),
        )
        .unwrap();
        let key = key();
        let startup = StateStoreInitializer::open(encrypted_path)
            .expect("lock")
            .initialize(&key);
        let mut random = Random(VecDeque::from([vec![3; 12]]));

        let loaded = match PlaintextMigration.migrate_startup(startup, &key, &mut random, now) {
            MigrationStartupOutcome::Migrated(loaded) => loaded,
            _ => panic!("expected completed migration"),
        };
        assert!(!legacy_path.exists());
        let snapshot = loaded.snapshot();
        assert_eq!(snapshot.revision(), 1);
        let payload: super::MigratedHistory = serde_json::from_slice(snapshot.payload()).unwrap();
        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.written_at, now);
        assert_eq!(payload.history.len(), 1);
        assert_eq!(payload.history[0].code, "123456");
        assert!(payload.history[0].source_message_digest.len() == 64);
        assert!(!String::from_utf8_lossy(snapshot.payload()).contains("message-1"));
        assert!(payload.seen_messages.is_empty() && payload.effect_outbox.is_empty());
        assert_eq!(payload.settings.history_retention_days, 7);
        assert_eq!(payload.settings.auto_copy_consent, "unknown");
        assert!(
            !payload.settings.auto_copy_global_enabled && !payload.settings.notification_enabled
        );
    }

    #[test]
    fn malformed_plaintext_is_preserved_before_any_encrypted_commit() {
        let directory = TestDirectory::new();
        let encrypted_path = state_path(&directory);
        let legacy_path = directory.0.join("code_history.json");
        fs::write(&legacy_path, b"not json").unwrap();
        let key = key();
        let startup = StateStoreInitializer::open(encrypted_path.clone())
            .expect("lock")
            .initialize(&key);
        let mut random = Random(VecDeque::from([vec![3; 12]]));

        match PlaintextMigration.migrate_startup(startup, &key, &mut random, 1_700_000_000_000) {
            MigrationStartupOutcome::RecoveryRequired { recovery, error } => {
                assert_eq!(error, MigrationError::LegacyInvalid);
                assert!(recovery.intake_stopped());
            }
            _ => panic!("invalid plaintext must retain recovery ownership"),
        }
        assert_eq!(fs::read(&legacy_path).unwrap(), b"not json");
        assert!(!encrypted_path.exists());
    }

    #[test]
    fn legacy_retention_uses_epoch_milliseconds_and_keeps_at_most_fifty_entries() {
        let now = 1_700_000_000_000;
        let directory = TestDirectory::new();
        let legacy_path = directory.0.join("code_history.json");
        fs::write(
            &legacy_path,
            serde_json::to_vec(&vec![
                legacy_entry(now - super::LEGACY_RETENTION_MILLISECONDS),
                legacy_entry(now - super::LEGACY_RETENTION_MILLISECONDS - 1),
            ])
            .unwrap(),
        )
        .unwrap();
        let boundary = super::read_legacy(&legacy_path, now).unwrap().unwrap();
        assert_eq!(boundary.len(), 1);
        assert_eq!(
            boundary[0].timestamp,
            now - super::LEGACY_RETENTION_MILLISECONDS
        );
        let mut entries = Vec::new();
        for offset in 0..51_i64 {
            let mut entry = legacy_entry(now - offset);
            entry.message_id = format!("message-{offset}");
            entries.push(entry);
        }
        entries.push(legacy_entry(now - super::LEGACY_RETENTION_MILLISECONDS));
        entries.push(legacy_entry(now - super::LEGACY_RETENTION_MILLISECONDS - 1));
        fs::write(&legacy_path, serde_json::to_vec(&entries).unwrap()).unwrap();

        let retained = super::read_legacy(&legacy_path, now).unwrap().unwrap();
        assert_eq!(retained.len(), 50);
        assert_eq!(retained[0].timestamp, now);
        assert_eq!(retained[49].timestamp, now - 49);
    }

    #[test]
    fn oversized_or_symlinked_legacy_input_enters_safe_migration_failure() {
        let directory = TestDirectory::new();
        let encrypted_path = state_path(&directory);
        let legacy_path = directory.0.join("code_history.json");
        fs::write(
            &legacy_path,
            vec![b'x'; super::MAX_LEGACY_PLAINTEXT_BYTES + 1],
        )
        .unwrap();
        let key = key();
        let startup = StateStoreInitializer::open(encrypted_path)
            .expect("lock")
            .initialize(&key);
        let mut random = Random(VecDeque::new());
        assert!(matches!(
            PlaintextMigration.migrate_startup(startup, &key, &mut random, 1_700_000_000_000),
            MigrationStartupOutcome::RecoveryRequired {
                error: MigrationError::LegacyReadFailed,
                ..
            }
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            fs::remove_file(&legacy_path).unwrap();
            let target = directory.0.join("target");
            fs::write(&target, b"[]").unwrap();
            symlink(&target, &legacy_path).unwrap();
            assert_eq!(
                super::read_legacy(&legacy_path, 1_700_000_000_000),
                Err(MigrationError::LegacyUnsafeEntry)
            );
        }
    }

    #[test]
    fn random_failure_after_marker_preparation_preserves_plaintext() {
        let directory = TestDirectory::new();
        let encrypted_path = state_path(&directory);
        let legacy_path = directory.0.join("code_history.json");
        let now = 1_700_000_000_000;
        fs::write(
            &legacy_path,
            serde_json::to_vec(&vec![legacy_entry(now)]).unwrap(),
        )
        .unwrap();
        let key = key();
        let startup = StateStoreInitializer::open(encrypted_path.clone())
            .expect("lock")
            .initialize(&key);
        let mut random = Random(VecDeque::new());

        assert!(matches!(
            PlaintextMigration.migrate_startup(startup, &key, &mut random, now),
            MigrationStartupOutcome::RecoveryRequired {
                error: MigrationError::StoreCommitUncommitted,
                ..
            }
        ));
        assert!(legacy_path.exists());
        assert!(!encrypted_path.exists());
        assert!(super::marker_path(&legacy_path).unwrap().exists());
    }

    #[test]
    fn invalid_marker_preserves_plaintext_before_any_encrypted_commit() {
        let directory = TestDirectory::new();
        let encrypted_path = state_path(&directory);
        let legacy_path = directory.0.join("code_history.json");
        let now = 1_700_000_000_000;
        fs::write(
            &legacy_path,
            serde_json::to_vec(&vec![legacy_entry(now)]).unwrap(),
        )
        .unwrap();
        fs::write(super::marker_path(&legacy_path).unwrap(), b"invalid marker").unwrap();
        let key = key();
        let startup = StateStoreInitializer::open(encrypted_path.clone())
            .expect("lock")
            .initialize(&key);
        let mut random = Random(VecDeque::new());

        assert!(matches!(
            PlaintextMigration.migrate_startup(startup, &key, &mut random, now),
            MigrationStartupOutcome::RecoveryRequired {
                error: MigrationError::MarkerInvalid,
                ..
            }
        ));
        assert!(legacy_path.exists());
        assert!(!encrypted_path.exists());
    }

    #[test]
    fn encrypted_commit_with_remaining_plaintext_resumes_deletion_without_duplicate_import() {
        let directory = TestDirectory::new();
        let encrypted_path = state_path(&directory);
        let legacy_path = directory.0.join("code_history.json");
        let now = 1_700_000_000_000;
        let entries = vec![legacy_entry(now)];
        let raw = serde_json::to_vec(&entries).unwrap();
        fs::write(&legacy_path, &raw).unwrap();
        let key = key();
        super::write_marker(
            &super::marker_path(&legacy_path).unwrap(),
            &super::MigrationMarker {
                format_version: super::MARKER_FORMAT_VERSION,
                phase: super::MarkerPhase::Prepared,
                migration_timestamp_ms: now,
                legacy_digest: super::legacy_digest(&key, &raw),
                ciphertext_sha256: None,
            },
        )
        .unwrap();
        let mut first = open_absent(encrypted_path.clone(), &key);
        let payload = super::canonical_payload(entries, &key, now).unwrap();
        let mut random = Random(VecDeque::from([vec![3; 12]]));
        assert!(matches!(
            first.commit(Snapshot::new(1, payload), &key, &mut random),
            crate::state_store::CommitOutcome::Committed(_)
        ));
        drop(first);

        let startup = StateStoreInitializer::open(encrypted_path)
            .expect("lock")
            .initialize(&key);
        assert!(matches!(
            PlaintextMigration.migrate_startup(
                startup,
                &key,
                &mut Random(VecDeque::new()),
                now + super::LEGACY_RETENTION_MILLISECONDS * 2,
            ),
            MigrationStartupOutcome::Migrated(_)
        ));
        assert!(!legacy_path.exists());
    }

    #[test]
    fn verified_marker_after_plaintext_delete_is_removed_safely_on_restart() {
        let directory = TestDirectory::new();
        let encrypted_path = state_path(&directory);
        let legacy_path = directory.0.join("code_history.json");
        let key = key();
        let mut store = open_absent(encrypted_path.clone(), &key);
        let payload = super::canonical_payload(vec![], &key, 1_700_000_000_000).unwrap();
        let mut random = Random(VecDeque::from([vec![3; 12]]));
        assert!(matches!(
            store.commit(Snapshot::new(1, payload.clone()), &key, &mut random),
            crate::state_store::CommitOutcome::Committed(_)
        ));
        let marker_path = super::marker_path(&legacy_path).unwrap();
        super::write_marker(
            &marker_path,
            &super::MigrationMarker {
                format_version: super::MARKER_FORMAT_VERSION,
                phase: super::MarkerPhase::EncryptedVerified,
                migration_timestamp_ms: 1_700_000_000_000,
                legacy_digest: super::legacy_digest(&key, b"[]"),
                ciphertext_sha256: Some(
                    super::migration_ciphertext_digest(&mut store, &key, Some(&payload)).unwrap(),
                ),
            },
        )
        .unwrap();
        let pending = super::pending_delete_path(&legacy_path).unwrap();
        fs::write(&pending, b"[]").unwrap();
        drop(store);

        let startup = StateStoreInitializer::open(encrypted_path)
            .expect("lock")
            .initialize(&key);
        let mut restart_random = Random(VecDeque::new());
        match PlaintextMigration.migrate_startup(
            startup,
            &key,
            &mut restart_random,
            1_700_000_000_000,
        ) {
            MigrationStartupOutcome::Migrated(loaded) => {
                assert_eq!(loaded.snapshot().revision(), 1)
            }
            _ => panic!("verified marker must resume cleanup"),
        }
        assert!(!marker_path.exists());
        assert!(!pending.exists());
    }

    #[test]
    fn concurrent_plaintext_replacement_is_preserved_and_never_unlinked() {
        let directory = TestDirectory::new();
        let legacy_path = directory.0.join("code_history.json");
        let pending = super::pending_delete_path(&legacy_path).unwrap();
        let key = key();
        let original = b"original legacy bytes";
        let replacement = b"concurrent replacement";
        fs::write(&legacy_path, replacement).unwrap();
        let marker = super::MigrationMarker {
            format_version: super::MARKER_FORMAT_VERSION,
            phase: super::MarkerPhase::EncryptedVerified,
            migration_timestamp_ms: 1_700_000_000_000,
            legacy_digest: super::legacy_digest(&key, original),
            ciphertext_sha256: Some("00".repeat(32)),
        };

        assert_eq!(
            super::move_verify_and_delete_plaintext(&legacy_path, &pending, &key, &marker),
            Err(MigrationError::LegacyChangedBeforeDelete)
        );
        assert_eq!(fs::read(&legacy_path).unwrap(), replacement);
        assert!(!pending.exists());
    }

    #[test]
    fn concurrently_recreated_plaintext_blocks_marker_removal_and_success() {
        let directory = TestDirectory::new();
        let legacy_path = directory.0.join("code_history.json");
        let marker_path = super::marker_path(&legacy_path).unwrap();
        fs::write(&legacy_path, b"recreated plaintext").unwrap();
        fs::write(&marker_path, b"marker remains").unwrap();

        assert_eq!(
            super::finish_marker_cleanup(&legacy_path, &marker_path),
            Err(MigrationError::LegacyRecreatedAfterDelete)
        );
        assert_eq!(fs::read(&legacy_path).unwrap(), b"recreated plaintext");
        assert!(marker_path.exists());
    }
}
