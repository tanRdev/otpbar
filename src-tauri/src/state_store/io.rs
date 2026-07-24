use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::ports::{RandomSource, SecretStore};

use super::crypto::{
    create_first_run_key, decode, decrypt, encode, encrypt, load_existing_key, CryptoError,
    Snapshot, StateKey,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Maximum serialized domain payload derived from the 50-item History,
/// 10,000-item Seen ledger, bounded effect metadata, and settings.
pub const MAX_SNAPSHOT_PAYLOAD: usize = 2 * 1024 * 1024;
/// Maximum JSON envelope, allowing worst-case byte-array JSON expansion.
pub const MAX_ENVELOPE_BYTES: usize = MAX_SNAPSHOT_PAYLOAD * 4 + 64 * 1024;
/// Maximum crash-left owned temporary files inspected during startup.
pub const MAX_OWNED_TEMPS: usize = 16;

trait FileSystem: Send + Sync {
    fn write_temp(&self, destination: &Path, bytes: &[u8]) -> io::Result<PathBuf>;
    fn sync_temp(&self, temp: &Path) -> io::Result<()>;
    fn replace(&self, temp: &Path, destination: &Path) -> io::Result<()>;
    fn sync_parent(&self, destination: &Path) -> io::Result<()>;
    fn read_limited(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>>;
    fn remove_temp(&self, path: &Path) -> io::Result<()>;
    fn discover_owned_temps(&self, destination: &Path) -> io::Result<Vec<PathBuf>>;
    fn inspect(&self, path: &Path) -> io::Result<EntryKind>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Missing,
    Regular,
    Rejected,
}

struct ProductionFileSystem;

impl FileSystem for ProductionFileSystem {
    fn write_temp(&self, destination: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("state path has no parent"))?;
        let file_name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("state path has no file name"))?;

        for _ in 0..16 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp = parent.join(format!(
                ".{file_name}.{}.{}.tmp",
                std::process::id(),
                sequence
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
            {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(bytes) {
                        drop(file);
                        let _ = fs::remove_file(&temp);
                        return Err(error);
                    }
                    return Ok(temp);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate state temp file",
        ))
    }

    fn sync_temp(&self, temp: &Path) -> io::Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(temp)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::other("state temp is not a regular file"));
        }
        file.sync_all()
    }

    fn replace(&self, temp: &Path, destination: &Path) -> io::Result<()> {
        fs::rename(temp, destination)
    }

    fn sync_parent(&self, destination: &Path) -> io::Result<()> {
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("state path has no parent"))?;
        File::open(parent)?.sync_all()
    }

    fn read_limited(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::other("state entry is not a regular file"));
        }
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        std::io::Read::by_ref(&mut file)
            .take((limit as u64) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "state entry exceeds limit",
            ));
        }
        Ok(bytes)
    }

    fn remove_temp(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn discover_owned_temps(&self, destination: &Path) -> io::Result<Vec<PathBuf>> {
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("state path has no parent"))?;
        let mut owned = Vec::new();
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            if is_owned_temp_name(destination, &entry.file_name().to_string_lossy()) {
                owned.push(entry.path());
                if owned.len() > MAX_OWNED_TEMPS {
                    break;
                }
            }
        }
        owned.sort();
        Ok(owned)
    }

    fn inspect(&self, path: &Path) -> io::Result<EntryKind> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(EntryKind::Regular),
            Ok(_) => Ok(EntryKind::Rejected),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(EntryKind::Missing),
            Err(error) => Err(error),
        }
    }
}

fn is_owned_temp_name(destination: &Path, candidate: &str) -> bool {
    let Some(file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let prefix = format!(".{file_name}.");
    let Some(middle) = candidate
        .strip_prefix(&prefix)
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut parts = middle.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(pid), Some(sequence), None)
            if !pid.is_empty()
                && !sequence.is_empty()
                && pid.bytes().all(|byte| byte.is_ascii_digit())
                && sequence.bytes().all(|byte| byte.is_ascii_digit())
    )
}

struct StoreLock {
    _file: Option<File>,
}

impl StoreLock {
    fn acquire(destination: &Path) -> Result<Self, OpenError> {
        let parent = destination.parent().ok_or(OpenError::Unavailable)?;
        let file_name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(OpenError::Unavailable)?;
        let lock_path = parent.join(format!(".{file_name}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)
            .map_err(|_| OpenError::Unavailable)?;
        let metadata = file.metadata().map_err(|_| OpenError::Unavailable)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(OpenError::Unavailable);
        }
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self { _file: Some(file) }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(OpenError::StoreInUse),
            Err(_) => Err(OpenError::Unavailable),
        }
    }

    #[cfg(test)]
    fn test() -> Self {
        Self { _file: None }
    }
}

/// Failure to acquire exclusive process ownership of a state store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Another process owns the store.
    StoreInUse,
    /// The owner-only lock could not be safely opened.
    Unavailable,
}

/// Authenticated identity used to verify the exact proposed snapshot after fsync.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SnapshotIdentity {
    revision: u64,
    checksum: [u8; 32],
}

impl std::fmt::Debug for SnapshotIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotIdentity")
            .field("revision", &self.revision)
            .field("checksum", &"[redacted]")
            .finish()
    }
}

impl SnapshotIdentity {
    /// Returns the monotonic state revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Computes an in-memory identity without exposing its payload-derived checksum.
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"otpbar-snapshot-identity-v1");
        digest.update(snapshot.revision().to_be_bytes());
        digest.update(snapshot.payload());
        Self {
            revision: snapshot.revision(),
            checksum: digest.finalize().into(),
        }
    }
}

/// Recovery reasons that never disclose ciphertext or plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    /// The expected state file disappeared after a successful durability barrier.
    Missing,
    /// Local storage could not be read.
    ReadFailed,
    /// The encrypted envelope or plaintext failed authentication/validation.
    AuthenticationFailed,
    /// The envelope or plaintext schema is newer or otherwise unsupported.
    UnsupportedFormat,
    /// Authenticated state did not match either permitted revision.
    UnexpectedSnapshot,
    /// A strictly owned crash-left temporary file was not authenticated.
    InvalidTemporaryState,
    /// A validated crash-left temporary file could not be durably removed.
    TemporaryCleanupFailed,
    /// Encrypted state exists but the Keychain key is missing.
    MissingKey,
    /// State exceeds a documented bound.
    OversizedState,
    /// More owned temporary files exist than startup will inspect.
    TooManyTemporaryFiles,
    /// A state path is a symlink or another non-regular entry.
    UnsafeEntryType,
}

/// Observable result of proposing an atomic snapshot replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The barrier and exact expected-new verification both completed.
    Committed(SnapshotIdentity),
    /// Failure happened before replace; the proposal did not commit.
    Uncommitted,
    /// Replace succeeded but the parent-directory durability barrier failed.
    BarrierPending,
    /// A passed barrier did not yield exactly the expected authenticated state.
    RecoveryRequired(RecoveryReason),
    /// The store already has an unresolved barrier or recovery invariant.
    Blocked,
    /// The proposal violates a pre-I/O model constraint.
    Rejected(CommitRejection),
}

/// Checked proposal failures that never mutate the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRejection {
    /// The opaque model payload exceeds [`MAX_SNAPSHOT_PAYLOAD`].
    PayloadTooLarge,
    /// Revision is not exactly the authoritative revision plus one.
    RevisionNotNext,
    /// The authoritative revision cannot be incremented.
    RevisionOverflow,
    /// The encoded envelope exceeds [`MAX_ENVELOPE_BYTES`].
    EnvelopeTooLarge,
}

/// Result of retrying the only legal operation after an indeterminate barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierRetryOutcome {
    /// Parent-directory fsync still fails; reads remain forbidden.
    StillPending,
    /// The retry barrier passed and exact expected-new verification succeeded.
    Committed(SnapshotIdentity),
    /// The retry barrier passed but verification found a broken invariant.
    RecoveryRequired(RecoveryReason),
    /// There was no pending barrier to retry.
    NotPending,
}

/// Startup classification of whichever authenticated snapshot survived.
pub enum StartupOutcome {
    /// No authoritative state survived; first-run or prior-absent startup may continue.
    Absent(AtomicStateStore),
    /// Authenticated state loaded; pending/claimed automatic effects must be canceled.
    LoadedMustCancelEffects(LoadedStartup),
    /// State was unreadable or did not match an allowed revision.
    RecoveryRequired(RecoveryReason),
}

impl std::fmt::Debug for StartupOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent(_) => formatter.write_str("Absent"),
            Self::LoadedMustCancelEffects(loaded) => formatter
                .debug_struct("LoadedMustCancelEffects")
                .field("revision", &loaded.snapshot.revision())
                .finish(),
            Self::RecoveryRequired(reason) => formatter
                .debug_tuple("RecoveryRequired")
                .field(reason)
                .finish(),
        }
    }
}

/// Authenticated startup state that requires effect cancellation before activation.
#[allow(dead_code)] // Task 20 consumes the retained store through the typed transition below.
pub struct LoadedStartup {
    store: AtomicStateStore,
    snapshot: Snapshot,
}

impl LoadedStartup {
    /// Returns the authoritative snapshot used to cancel pending/claimed effects.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Releases the store solely to durably commit pending/claimed cancellation.
    ///
    /// Intake and automatic effects must remain stopped until that commit
    /// returns [`CommitOutcome::Committed`]. Task 20 owns this orchestration.
    #[allow(dead_code)] // Deliberately unavailable outside this crate until Task 20 integrates it.
    pub(crate) fn into_store_for_effect_cancellation(self) -> AtomicStateStore {
        self.store
    }
}

/// Opaque proof that startup observed neither a state key nor local state.
///
/// This type cannot be constructed by callers. Consuming it rechecks local
/// state before any Keychain write.
pub struct FirstRunKeyCapability {
    initializer: StateStoreInitializer,
}

impl FirstRunKeyCapability {
    /// Rechecks the no-state proof, then creates the first-run key and store.
    pub fn create(
        self,
        secrets: &mut impl SecretStore,
        random: &mut impl RandomSource,
    ) -> Result<FirstRunCreationOutcome, CryptoError> {
        match self.initializer.inspect_state_presence() {
            Ok(true) => return Ok(FirstRunCreationOutcome::StateAppeared),
            Ok(false) => {}
            Err(reason) => return Ok(FirstRunCreationOutcome::RecoveryRequired(reason)),
        }
        let key = create_first_run_key(secrets, random)?;
        let outcome = self.initializer.initialize(&key);
        Ok(FirstRunCreationOutcome::KeyCreated { key, outcome })
    }
}

/// Result of consuming a first-run key capability.
pub enum FirstRunCreationOutcome {
    /// The key was created; startup was re-evaluated and may require recovery.
    KeyCreated {
        /// Newly persisted application-readable key.
        key: StateKey,
        /// Actual post-write startup classification.
        outcome: StartupOutcome,
    },
    /// State appeared before capability consumption; no key was written.
    StateAppeared,
    /// State presence could not be inspected safely; no key was written.
    RecoveryRequired(RecoveryReason),
}

/// Key-aware startup result that cannot create a key over existing ciphertext.
pub enum SecretStartupOutcome {
    /// No state and no key exist; the caller may explicitly create a first-run key.
    FirstRunNeedsKey(FirstRunKeyCapability),
    /// An existing key was used to inspect state and remains available to the live store.
    Initialized {
        /// The authenticated startup classification.
        outcome: StartupOutcome,
        /// The application-readable state key.
        key: StateKey,
    },
    /// Ciphertext exists but its Keychain key is absent.
    RecoveryRequired(RecoveryReason),
}

/// Why an ordinary read is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreAccessError {
    /// Read-back is forbidden until the parent-directory fsync retry succeeds.
    BarrierPending,
    /// The store is preserving an unreadable or invariant-breaking file for recovery.
    RecoveryRequired(RecoveryReason),
}

#[derive(Clone, Copy)]
enum StorePhase {
    Ready(AuthoritativeState),
    BarrierPending(SnapshotIdentity),
    Recovery(RecoveryReason),
}

#[derive(Clone, Copy)]
enum AuthoritativeState {
    Absent,
    At(SnapshotIdentity),
}

/// Stateful encrypted atomic snapshot store.
pub struct AtomicStateStore {
    path: PathBuf,
    filesystem: Box<dyn FileSystem>,
    phase: StorePhase,
    _lock: StoreLock,
}

/// One-way startup path, distinct from operations on a live store.
pub struct StateStoreInitializer {
    path: PathBuf,
    filesystem: Box<dyn FileSystem>,
    lock: StoreLock,
}

impl StateStoreInitializer {
    /// Acquires exclusive process ownership before inspecting state or Keychain.
    pub fn open(path: PathBuf) -> Result<Self, OpenError> {
        let lock = StoreLock::acquire(&path)?;
        Ok(Self {
            path,
            filesystem: Box::new(ProductionFileSystem),
            lock,
        })
    }

    /// Loads the existing key without ever minting one over ciphertext.
    pub fn initialize_from_secrets(
        self,
        secrets: &impl SecretStore,
    ) -> Result<SecretStartupOutcome, CryptoError> {
        match load_existing_key(secrets)? {
            Some(key) => {
                let outcome = self.initialize(&key);
                Ok(SecretStartupOutcome::Initialized { outcome, key })
            }
            None => match self.inspect_state_presence() {
                Ok(true) => Ok(SecretStartupOutcome::RecoveryRequired(
                    RecoveryReason::MissingKey,
                )),
                Ok(false) => Ok(SecretStartupOutcome::FirstRunNeedsKey(
                    FirstRunKeyCapability { initializer: self },
                )),
                Err(reason) => Ok(SecretStartupOutcome::RecoveryRequired(reason)),
            },
        }
    }

    /// Authenticates startup state and consumes the initializer.
    pub fn initialize(self, key: &StateKey) -> StartupOutcome {
        initialize_store(self.path, self.filesystem, self.lock, key)
    }

    fn inspect_state_presence(&self) -> Result<bool, RecoveryReason> {
        match self
            .filesystem
            .inspect(&self.path)
            .map_err(|_| RecoveryReason::ReadFailed)?
        {
            EntryKind::Regular => return Ok(true),
            EntryKind::Rejected => return Err(RecoveryReason::UnsafeEntryType),
            EntryKind::Missing => {}
        }
        let temps = self
            .filesystem
            .discover_owned_temps(&self.path)
            .map_err(|_| RecoveryReason::ReadFailed)?;
        if temps.len() > MAX_OWNED_TEMPS {
            return Err(RecoveryReason::TooManyTemporaryFiles);
        }
        Ok(!temps.is_empty())
    }

    #[cfg(test)]
    fn with_filesystem(path: PathBuf, filesystem: impl FileSystem + 'static) -> Self {
        Self {
            path,
            filesystem: Box::new(filesystem),
            lock: StoreLock::test(),
        }
    }
}

impl AtomicStateStore {
    #[cfg(test)]
    fn with_filesystem(path: PathBuf, filesystem: impl FileSystem + 'static) -> Self {
        Self {
            path,
            filesystem: Box::new(filesystem),
            phase: StorePhase::Ready(AuthoritativeState::Absent),
            _lock: StoreLock::test(),
        }
    }

    /// Writes, syncs, replaces, crosses the directory barrier, and verifies expected-new.
    pub fn commit(
        &mut self,
        snapshot: Snapshot,
        key: &StateKey,
        random: &mut impl RandomSource,
    ) -> CommitOutcome {
        let StorePhase::Ready(authoritative) = self.phase else {
            return CommitOutcome::Blocked;
        };
        if snapshot.payload().len() > MAX_SNAPSHOT_PAYLOAD {
            return CommitOutcome::Rejected(CommitRejection::PayloadTooLarge);
        }
        let next_revision = match authoritative {
            AuthoritativeState::Absent => 1,
            AuthoritativeState::At(identity) => match identity.revision().checked_add(1) {
                Some(revision) => revision,
                None => return CommitOutcome::Rejected(CommitRejection::RevisionOverflow),
            },
        };
        if snapshot.revision() != next_revision {
            return CommitOutcome::Rejected(CommitRejection::RevisionNotNext);
        }
        if let Err(reason) = self.verify_authoritative(key, authoritative) {
            self.phase = StorePhase::Recovery(reason);
            return CommitOutcome::RecoveryRequired(reason);
        }
        let expected = SnapshotIdentity::from_snapshot(&snapshot);
        let bytes = match encrypt(&snapshot, key, random).and_then(|envelope| encode(&envelope)) {
            Ok(bytes) => bytes,
            Err(_) => return CommitOutcome::Uncommitted,
        };
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return CommitOutcome::Rejected(CommitRejection::EnvelopeTooLarge);
        }
        let temp = match self.filesystem.write_temp(&self.path, &bytes) {
            Ok(temp) => temp,
            Err(_) => return CommitOutcome::Uncommitted,
        };
        if self.filesystem.sync_temp(&temp).is_err() {
            let _ = self.filesystem.remove_temp(&temp);
            return CommitOutcome::Uncommitted;
        }
        if self.filesystem.replace(&temp, &self.path).is_err() {
            let _ = self.filesystem.remove_temp(&temp);
            return CommitOutcome::Uncommitted;
        }
        if self.filesystem.sync_parent(&self.path).is_err() {
            self.phase = StorePhase::BarrierPending(expected);
            return CommitOutcome::BarrierPending;
        }
        self.resolve_expected(key, expected)
    }

    /// Retries only the parent-directory durability barrier, then verifies expected-new.
    pub fn retry_barrier(&mut self, key: &StateKey) -> BarrierRetryOutcome {
        let StorePhase::BarrierPending(expected) = self.phase else {
            return BarrierRetryOutcome::NotPending;
        };
        if self.filesystem.sync_parent(&self.path).is_err() {
            return BarrierRetryOutcome::StillPending;
        }
        match self.resolve_expected(key, expected) {
            CommitOutcome::Committed(identity) => BarrierRetryOutcome::Committed(identity),
            CommitOutcome::RecoveryRequired(reason) => {
                BarrierRetryOutcome::RecoveryRequired(reason)
            }
            _ => unreachable!("expected verification has only terminal outcomes"),
        }
    }

    /// Reads authenticated state only while no barrier or recovery invariant is unresolved.
    pub fn load(&mut self, key: &StateKey) -> Result<Option<Snapshot>, StoreAccessError> {
        match self.phase {
            StorePhase::BarrierPending(_) => Err(StoreAccessError::BarrierPending),
            StorePhase::Recovery(reason) => Err(StoreAccessError::RecoveryRequired(reason)),
            StorePhase::Ready(authoritative) => match self.verify_and_load(key, authoritative) {
                Ok(snapshot) => Ok(snapshot),
                Err(reason) => {
                    self.phase = StorePhase::Recovery(reason);
                    Err(StoreAccessError::RecoveryRequired(reason))
                }
            },
        }
    }

    fn resolve_expected(&mut self, key: &StateKey, expected: SnapshotIdentity) -> CommitOutcome {
        match self.read_authenticated(key) {
            Ok(snapshot) if SnapshotIdentity::from_snapshot(&snapshot) == expected => {
                self.phase = StorePhase::Ready(AuthoritativeState::At(expected));
                CommitOutcome::Committed(expected)
            }
            Ok(_) => {
                self.phase = StorePhase::Recovery(RecoveryReason::UnexpectedSnapshot);
                CommitOutcome::RecoveryRequired(RecoveryReason::UnexpectedSnapshot)
            }
            Err(reason) => {
                self.phase = StorePhase::Recovery(reason);
                CommitOutcome::RecoveryRequired(reason)
            }
        }
    }

    fn read_authenticated(&self, key: &StateKey) -> Result<Snapshot, RecoveryReason> {
        match self
            .filesystem
            .inspect(&self.path)
            .map_err(|_| RecoveryReason::ReadFailed)?
        {
            EntryKind::Missing => return Err(RecoveryReason::Missing),
            EntryKind::Rejected => return Err(RecoveryReason::UnsafeEntryType),
            EntryKind::Regular => {}
        }
        let bytes = self
            .filesystem
            .read_limited(&self.path, MAX_ENVELOPE_BYTES)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    RecoveryReason::Missing
                } else if error.kind() == io::ErrorKind::FileTooLarge {
                    RecoveryReason::OversizedState
                } else {
                    RecoveryReason::ReadFailed
                }
            })?;
        let envelope = decode(&bytes).map_err(map_crypto_error)?;
        let snapshot = decrypt(&envelope, key).map_err(map_crypto_error)?;
        if snapshot.payload().len() > MAX_SNAPSHOT_PAYLOAD {
            return Err(RecoveryReason::OversizedState);
        }
        Ok(snapshot)
    }

    fn verify_authoritative(
        &self,
        key: &StateKey,
        authoritative: AuthoritativeState,
    ) -> Result<(), RecoveryReason> {
        self.verify_and_load(key, authoritative).map(|_| ())
    }

    fn verify_and_load(
        &self,
        key: &StateKey,
        authoritative: AuthoritativeState,
    ) -> Result<Option<Snapshot>, RecoveryReason> {
        match authoritative {
            AuthoritativeState::Absent => match self
                .filesystem
                .inspect(&self.path)
                .map_err(|_| RecoveryReason::ReadFailed)?
            {
                EntryKind::Missing => Ok(None),
                EntryKind::Rejected => Err(RecoveryReason::UnsafeEntryType),
                EntryKind::Regular => Err(RecoveryReason::UnexpectedSnapshot),
            },
            AuthoritativeState::At(expected) => {
                let snapshot = self.read_authenticated(key)?;
                if SnapshotIdentity::from_snapshot(&snapshot) == expected {
                    Ok(Some(snapshot))
                } else {
                    Err(RecoveryReason::UnexpectedSnapshot)
                }
            }
        }
    }
}

fn initialize_store(
    path: PathBuf,
    filesystem: Box<dyn FileSystem>,
    lock: StoreLock,
    key: &StateKey,
) -> StartupOutcome {
    let mut store = AtomicStateStore {
        path,
        filesystem,
        phase: StorePhase::Ready(AuthoritativeState::Absent),
        _lock: lock,
    };
    let temps = match store.filesystem.discover_owned_temps(&store.path) {
        Ok(temps) => temps,
        Err(_) => return StartupOutcome::RecoveryRequired(RecoveryReason::ReadFailed),
    };
    if temps.len() > MAX_OWNED_TEMPS {
        return StartupOutcome::RecoveryRequired(RecoveryReason::TooManyTemporaryFiles);
    }
    for temp in temps {
        let valid = store
            .filesystem
            .read_limited(&temp, MAX_ENVELOPE_BYTES)
            .map_err(|_| RecoveryReason::InvalidTemporaryState)
            .and_then(|bytes| decode(&bytes).map_err(|_| RecoveryReason::InvalidTemporaryState))
            .and_then(|envelope| {
                let snapshot =
                    decrypt(&envelope, key).map_err(|_| RecoveryReason::InvalidTemporaryState)?;
                if snapshot.payload().len() > MAX_SNAPSHOT_PAYLOAD {
                    return Err(RecoveryReason::InvalidTemporaryState);
                }
                Ok(snapshot)
            });
        if valid.is_err() {
            return StartupOutcome::RecoveryRequired(RecoveryReason::InvalidTemporaryState);
        }
        if store.filesystem.remove_temp(&temp).is_err()
            || store.filesystem.sync_parent(&store.path).is_err()
        {
            return StartupOutcome::RecoveryRequired(RecoveryReason::TemporaryCleanupFailed);
        }
    }
    match store.read_authenticated(key) {
        Ok(snapshot) => {
            store.phase = StorePhase::Ready(AuthoritativeState::At(
                SnapshotIdentity::from_snapshot(&snapshot),
            ));
            StartupOutcome::LoadedMustCancelEffects(LoadedStartup { store, snapshot })
        }
        Err(RecoveryReason::Missing) => StartupOutcome::Absent(store),
        Err(reason) => StartupOutcome::RecoveryRequired(reason),
    }
}

fn map_crypto_error(error: CryptoError) -> RecoveryReason {
    match error {
        CryptoError::UnsupportedFormat => RecoveryReason::UnsupportedFormat,
        CryptoError::AuthenticationFailed
        | CryptoError::Encoding
        | CryptoError::InvalidStoredKey
        | CryptoError::KeyAlreadyExists
        | CryptoError::RandomUnavailable
        | CryptoError::SecretUnavailable => RecoveryReason::AuthenticationFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        fs, io,
        io::{BufRead, BufReader, Write},
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
    };

    use crate::{
        domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
        ports::{RandomSource, SecretStore},
        state_store::crypto::{encode, encrypt, key_from_bytes, Snapshot, StateKey},
    };

    use super::{
        is_owned_temp_name, AtomicStateStore, BarrierRetryOutcome, CommitOutcome, CommitRejection,
        EntryKind, FileSystem, FirstRunCreationOutcome, OpenError, RecoveryReason,
        SecretStartupOutcome, SnapshotIdentity, StartupOutcome, StateStoreInitializer,
        StoreAccessError, MAX_ENVELOPE_BYTES, MAX_OWNED_TEMPS, MAX_SNAPSHOT_PAYLOAD,
    };

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "otpbar-state-store-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove isolated test directory");
        }
    }

    #[derive(Default)]
    struct FakeState {
        files: HashMap<PathBuf, Vec<u8>>,
        fail_temp_write: bool,
        fail_temp_sync: bool,
        fail_replace: bool,
        sync_results: VecDeque<bool>,
        read_results: VecDeque<FakeRead>,
        read_count: usize,
        operations: Vec<&'static str>,
    }

    enum FakeRead {
        Actual,
        Bytes(Vec<u8>),
        Missing,
        Failed,
    }

    #[derive(Clone, Default)]
    struct FakeFileSystem(Arc<Mutex<FakeState>>);

    impl FileSystem for FakeFileSystem {
        fn write_temp(&self, destination: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
            let mut state = self.0.lock().expect("fake filesystem");
            state.operations.push("write_temp");
            if state.fail_temp_write {
                return Err(io::Error::other("injected temp write failure"));
            }
            let file_name = destination
                .file_name()
                .and_then(|name| name.to_str())
                .expect("test destination name");
            let temp = destination
                .parent()
                .expect("test destination parent")
                .join(format!(".{file_name}.123.456.tmp"));
            state.files.insert(temp.clone(), bytes.to_vec());
            Ok(temp)
        }

        fn sync_temp(&self, _temp: &Path) -> io::Result<()> {
            let mut state = self.0.lock().expect("fake filesystem");
            state.operations.push("sync_temp");
            if state.fail_temp_sync {
                Err(io::Error::other("injected temp sync failure"))
            } else {
                Ok(())
            }
        }

        fn replace(&self, temp: &Path, destination: &Path) -> io::Result<()> {
            let mut state = self.0.lock().expect("fake filesystem");
            state.operations.push("replace");
            if state.fail_replace {
                return Err(io::Error::other("injected replace failure"));
            }
            let bytes = state
                .files
                .remove(temp)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing temp"))?;
            state.files.insert(destination.to_path_buf(), bytes);
            Ok(())
        }

        fn sync_parent(&self, _destination: &Path) -> io::Result<()> {
            let mut state = self.0.lock().expect("fake filesystem");
            state.operations.push("sync_parent");
            let succeeds = state.sync_results.pop_front().unwrap_or(true);
            if succeeds {
                Ok(())
            } else {
                Err(io::Error::other("injected parent fsync failure"))
            }
        }

        fn read_limited(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
            let mut state = self.0.lock().expect("fake filesystem");
            state.operations.push("read");
            state.read_count += 1;
            match state.read_results.pop_front().unwrap_or(FakeRead::Actual) {
                FakeRead::Actual => state
                    .files
                    .get(path)
                    .cloned()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
                    .and_then(|bytes| {
                        if bytes.len() > limit {
                            Err(io::Error::new(io::ErrorKind::FileTooLarge, "oversized"))
                        } else {
                            Ok(bytes)
                        }
                    }),
                FakeRead::Bytes(bytes) if bytes.len() > limit => {
                    Err(io::Error::new(io::ErrorKind::FileTooLarge, "oversized"))
                }
                FakeRead::Bytes(bytes) => Ok(bytes),
                FakeRead::Missing => Err(io::Error::new(io::ErrorKind::NotFound, "missing")),
                FakeRead::Failed => Err(io::Error::other("injected read failure")),
            }
        }

        fn remove_temp(&self, path: &Path) -> io::Result<()> {
            self.0.lock().expect("fake filesystem").files.remove(path);
            Ok(())
        }

        fn discover_owned_temps(&self, destination: &Path) -> io::Result<Vec<PathBuf>> {
            let state = self.0.lock().expect("fake filesystem");
            let mut temps: Vec<_> = state
                .files
                .keys()
                .filter(|path| {
                    path.parent() == destination.parent()
                        && path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| is_owned_temp_name(destination, name))
                })
                .cloned()
                .collect();
            temps.sort();
            Ok(temps)
        }

        fn inspect(&self, path: &Path) -> io::Result<EntryKind> {
            Ok(
                if self
                    .0
                    .lock()
                    .expect("fake filesystem")
                    .files
                    .contains_key(path)
                {
                    EntryKind::Regular
                } else {
                    EntryKind::Missing
                },
            )
        }
    }

    struct SequenceRandom(VecDeque<Vec<u8>>);

    impl RandomSource for SequenceRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ErrorEnvelope> {
            let bytes = self.0.pop_front().ok_or_else(|| {
                ErrorEnvelope::new(
                    ErrorCode::StorageUnavailable,
                    UserMessage::LocalDataUnavailable,
                    false,
                )
            })?;
            destination.copy_from_slice(&bytes);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestSecrets {
        value: Option<Vec<u8>>,
        writes: usize,
        state_on_write: Option<(FakeFileSystem, PathBuf, Vec<u8>)>,
    }

    impl SecretStore for TestSecrets {
        fn read_secret(&self, _key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
            Ok(self.value.clone())
        }

        fn write_secret(&mut self, _key: &str, value: &[u8]) -> Result<(), ErrorEnvelope> {
            self.writes += 1;
            self.value = Some(value.to_vec());
            if let Some((filesystem, path, bytes)) = self.state_on_write.take() {
                filesystem
                    .0
                    .lock()
                    .expect("fake filesystem")
                    .files
                    .insert(path, bytes);
            }
            Ok(())
        }

        fn delete_secret(&mut self, _key: &str) -> Result<(), ErrorEnvelope> {
            self.value = None;
            Ok(())
        }
    }

    fn test_key() -> StateKey {
        key_from_bytes(&[0x11; 32]).expect("test key")
    }

    fn encrypted(snapshot: &Snapshot, key: &StateKey, nonce: u8) -> Vec<u8> {
        let mut random = SequenceRandom(VecDeque::from([vec![nonce; 12]]));
        let envelope = encrypt(snapshot, key, &mut random).expect("encrypt fixture");
        encode(&envelope).expect("encode fixture")
    }

    fn store_with_prior(
        path: &Path,
        filesystem: &FakeFileSystem,
        key: &StateKey,
        prior: &Snapshot,
    ) -> AtomicStateStore {
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .insert(path.to_path_buf(), encrypted(prior, key, 0x19));
        let initializer =
            StateStoreInitializer::with_filesystem(path.to_path_buf(), filesystem.clone());
        match initializer.initialize(key) {
            StartupOutcome::LoadedMustCancelEffects(loaded) => {
                loaded.into_store_for_effect_cancellation()
            }
            other => panic!("expected loaded prior: {other:?}"),
        }
    }

    #[test]
    fn failure_before_replace_is_uncommitted_and_preserves_prior_snapshot() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let mut store = store_with_prior(
            &path,
            &filesystem,
            &key,
            &Snapshot::new(1, b"prior".to_vec()),
        );
        let original = filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .get(&path)
            .cloned()
            .unwrap();
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .fail_temp_write = true;
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        let outcome = store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random);

        assert_eq!(outcome, CommitOutcome::Uncommitted);
        let state = filesystem.0.lock().expect("fake filesystem");
        assert_eq!(
            state.files.get(&path).map(Vec::as_slice),
            Some(original.as_slice())
        );
    }

    #[test]
    fn random_source_failure_is_pre_replace_and_uncommitted() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let mut store = store_with_prior(
            &path,
            &filesystem,
            &key,
            &Snapshot::new(1, b"prior".to_vec()),
        );
        let original = filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .get(&path)
            .cloned()
            .unwrap();
        let mut failing_random = SequenceRandom(VecDeque::new());

        assert_eq!(
            store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut failing_random),
            CommitOutcome::Uncommitted
        );
        let state = filesystem.0.lock().expect("fake filesystem");
        assert_eq!(state.operations.last(), Some(&"read"));
        assert_eq!(state.files.get(&path), Some(&original));
    }

    #[test]
    fn replace_failure_is_uncommitted_and_removes_non_authoritative_temp() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let mut store = store_with_prior(
            &path,
            &filesystem,
            &key,
            &Snapshot::new(1, b"prior".to_vec()),
        );
        let original = filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .get(&path)
            .cloned()
            .unwrap();
        filesystem.0.lock().expect("fake filesystem").fail_replace = true;
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        let outcome = store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random);

        assert_eq!(outcome, CommitOutcome::Uncommitted);
        let state = filesystem.0.lock().expect("fake filesystem");
        assert_eq!(
            state.files.get(&path).map(Vec::as_slice),
            Some(original.as_slice())
        );
        assert_eq!(state.files.len(), 1);
    }

    #[test]
    fn temp_file_sync_failure_prevents_replace_and_is_uncommitted() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        {
            let mut state = filesystem.0.lock().expect("fake filesystem");
            state.fail_temp_sync = true;
        }
        let key = test_key();
        let mut store = store_with_prior(
            &path,
            &filesystem,
            &key,
            &Snapshot::new(1, b"prior".to_vec()),
        );
        let original = filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .get(&path)
            .cloned()
            .unwrap();
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        assert_eq!(
            store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random),
            CommitOutcome::Uncommitted
        );
        let state = filesystem.0.lock().expect("fake filesystem");
        assert!(state
            .operations
            .ends_with(&["read", "write_temp", "sync_temp"]));
        assert_eq!(
            state.files.get(&path).map(Vec::as_slice),
            Some(original.as_slice())
        );
        assert_eq!(state.files.len(), 1);
    }

    #[test]
    fn failed_parent_barrier_forbids_immediate_readback_and_new_commit() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .sync_results
            .push_back(false);
        let mut store = AtomicStateStore::with_filesystem(path, filesystem.clone());
        let key = test_key();
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12], vec![0x33; 12]]));

        assert_eq!(
            store.commit(Snapshot::new(1, b"new".to_vec()), &key, &mut random),
            CommitOutcome::BarrierPending
        );
        assert!(matches!(
            store.load(&key),
            Err(StoreAccessError::BarrierPending)
        ));
        assert_eq!(
            store.commit(Snapshot::new(2, b"newer".to_vec()), &key, &mut random),
            CommitOutcome::Blocked
        );
        assert_eq!(filesystem.0.lock().expect("fake filesystem").read_count, 0);
    }

    #[test]
    fn barrier_retry_must_succeed_before_expected_new_verification() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .sync_results
            .extend([false, false, true]);
        let mut store = AtomicStateStore::with_filesystem(path, filesystem.clone());
        let key = test_key();
        let new = Snapshot::new(1, b"new".to_vec());
        let expected = SnapshotIdentity::from_snapshot(&new);
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        assert_eq!(
            store.commit(new, &key, &mut random),
            CommitOutcome::BarrierPending
        );
        assert_eq!(store.retry_barrier(&key), BarrierRetryOutcome::StillPending);
        assert_eq!(filesystem.0.lock().expect("fake filesystem").read_count, 0);
        assert_eq!(
            store.retry_barrier(&key),
            BarrierRetryOutcome::Committed(expected)
        );
        assert_eq!(filesystem.0.lock().expect("fake filesystem").read_count, 1);
    }

    #[test]
    fn successful_original_barrier_requires_exact_authenticated_new_snapshot() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let prior = Snapshot::new(1, b"prior".to_vec());
        let mismatch = Snapshot::new(9, b"other".to_vec());
        let cases = [
            (
                FakeRead::Bytes(encrypted(&prior, &key, 0x31)),
                RecoveryReason::UnexpectedSnapshot,
            ),
            (
                FakeRead::Bytes(b"unreadable".to_vec()),
                RecoveryReason::AuthenticationFailed,
            ),
            (FakeRead::Missing, RecoveryReason::Missing),
            (FakeRead::Failed, RecoveryReason::ReadFailed),
            (
                FakeRead::Bytes(encrypted(&mismatch, &key, 0x32)),
                RecoveryReason::UnexpectedSnapshot,
            ),
        ];

        for (read, reason) in cases {
            let filesystem = FakeFileSystem::default();
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .read_results
                .push_back(read);
            let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());
            let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

            assert_eq!(
                store.commit(Snapshot::new(1, b"new".to_vec()), &key, &mut random),
                CommitOutcome::RecoveryRequired(reason)
            );
            assert!(matches!(
                store.load(&key),
                Err(StoreAccessError::RecoveryRequired(actual)) if actual == reason
            ));
        }
    }

    #[test]
    fn successful_retry_barrier_still_recovers_on_prior_unreadable_or_mismatch() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let prior = Snapshot::new(1, b"prior".to_vec());
        let mismatch = Snapshot::new(9, b"other".to_vec());
        let cases = [
            (
                FakeRead::Bytes(encrypted(&prior, &key, 0x31)),
                RecoveryReason::UnexpectedSnapshot,
            ),
            (
                FakeRead::Bytes(b"unreadable".to_vec()),
                RecoveryReason::AuthenticationFailed,
            ),
            (
                FakeRead::Bytes(encrypted(&mismatch, &key, 0x32)),
                RecoveryReason::UnexpectedSnapshot,
            ),
            (FakeRead::Missing, RecoveryReason::Missing),
            (FakeRead::Failed, RecoveryReason::ReadFailed),
        ];

        for (read, reason) in cases {
            let filesystem = FakeFileSystem::default();
            {
                let mut state = filesystem.0.lock().expect("fake filesystem");
                state.sync_results.extend([false, true]);
                state.read_results.push_back(read);
            }
            let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());
            let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

            assert_eq!(
                store.commit(Snapshot::new(1, b"new".to_vec()), &key, &mut random),
                CommitOutcome::BarrierPending
            );
            assert_eq!(
                store.retry_barrier(&key),
                BarrierRetryOutcome::RecoveryRequired(reason)
            );
            assert!(matches!(
                store.load(&key),
                Err(StoreAccessError::RecoveryRequired(actual)) if actual == reason
            ));
        }
    }

    #[test]
    fn restart_loads_any_authenticated_survivor_with_cancel_effects_requirement() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let prior = Snapshot::new(1, b"prior".to_vec());
        let new = Snapshot::new(2, b"new".to_vec());
        let cases = [
            (encrypted(&prior, &key, 0x31), 1),
            (encrypted(&new, &key, 0x32), 2),
        ];

        for (survivor, expected_revision) in cases {
            let filesystem = FakeFileSystem::default();
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .insert(path.clone(), survivor);
            let initializer =
                StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone());

            match initializer.initialize(&key) {
                StartupOutcome::LoadedMustCancelEffects(loaded) => {
                    assert_eq!(loaded.snapshot().revision(), expected_revision);
                }
                other => panic!("unexpected startup outcome: {other:?}"),
            }
        }
    }

    #[test]
    fn crash_after_temp_sync_before_replace_cleans_valid_temp_and_loads_destination() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap();
        let temp = path
            .parent()
            .unwrap()
            .join(format!(".{file_name}.123.456.tmp"));
        let key = test_key();
        let prior = Snapshot::new(1, b"prior".to_vec());
        let proposed = Snapshot::new(2, b"proposed".to_vec());
        let filesystem = FakeFileSystem::default();
        {
            let mut state = filesystem.0.lock().expect("fake filesystem");
            state
                .files
                .insert(path.clone(), encrypted(&prior, &key, 0x31));
            state
                .files
                .insert(temp.clone(), encrypted(&proposed, &key, 0x32));
        }

        let initializer = StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone());
        match initializer.initialize(&key) {
            StartupOutcome::LoadedMustCancelEffects(loaded) => {
                assert_eq!(loaded.snapshot().revision(), 1);
            }
            other => panic!("unexpected startup outcome: {other:?}"),
        }
        let state = filesystem.0.lock().expect("fake filesystem");
        assert!(!state.files.contains_key(&temp));
        assert!(state.files.contains_key(&path));
    }

    #[test]
    fn startup_ignores_unowned_temp_names_but_preserves_invalid_owned_temp() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let destination = encrypted(&Snapshot::new(1, b"prior".to_vec()), &key, 0x31);
        let unowned = PathBuf::from("/state/otpbar-state.json.tmp");
        let owned = PathBuf::from("/state/.otpbar-state.json.123.456.tmp");

        let ignored_filesystem = FakeFileSystem::default();
        {
            let mut state = ignored_filesystem.0.lock().expect("fake filesystem");
            state.files.insert(path.clone(), destination.clone());
            state.files.insert(unowned.clone(), b"unrelated".to_vec());
        }
        let initializer =
            StateStoreInitializer::with_filesystem(path.clone(), ignored_filesystem.clone());
        assert!(matches!(
            initializer.initialize(&key),
            StartupOutcome::LoadedMustCancelEffects(_)
        ));
        assert!(ignored_filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .contains_key(&unowned));

        let invalid_filesystem = FakeFileSystem::default();
        {
            let mut state = invalid_filesystem.0.lock().expect("fake filesystem");
            state.files.insert(path.clone(), destination.clone());
            state.files.insert(owned.clone(), b"invalid".to_vec());
        }
        let initializer =
            StateStoreInitializer::with_filesystem(path.clone(), invalid_filesystem.clone());
        assert!(matches!(
            initializer.initialize(&key),
            StartupOutcome::RecoveryRequired(RecoveryReason::InvalidTemporaryState)
        ));
        let state = invalid_filesystem.0.lock().expect("fake filesystem");
        assert_eq!(state.files.get(&path), Some(&destination));
        assert_eq!(state.files.get(&owned), Some(&b"invalid".to_vec()));
    }

    #[test]
    fn missing_key_with_existing_ciphertext_preserves_state_and_creates_no_key() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let original = b"existing ciphertext".to_vec();
        let filesystem = FakeFileSystem::default();
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .insert(path.clone(), original.clone());
        let secrets = TestSecrets::default();
        let initializer = StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone());

        assert!(matches!(
            initializer
                .initialize_from_secrets(&secrets)
                .expect("key lookup"),
            SecretStartupOutcome::RecoveryRequired(RecoveryReason::MissingKey)
        ));
        assert_eq!(secrets.writes, 0);
        assert_eq!(
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .get(&path),
            Some(&original)
        );
    }

    #[test]
    fn absent_state_requires_explicit_first_run_key_creation() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let filesystem = FakeFileSystem::default();
        let mut secrets = TestSecrets::default();
        let initializer = StateStoreInitializer::with_filesystem(path, filesystem.clone());
        let capability = match initializer
            .initialize_from_secrets(&secrets)
            .expect("key lookup")
        {
            SecretStartupOutcome::FirstRunNeedsKey(capability) => capability,
            _ => panic!("first run must require explicit key creation"),
        };
        let mut random = SequenceRandom(VecDeque::from([vec![0x55; 32]]));
        let creation = capability
            .create(&mut secrets, &mut random)
            .expect("capability key creation");

        assert_eq!(secrets.writes, 1);
        assert!(matches!(
            creation,
            FirstRunCreationOutcome::KeyCreated {
                outcome: StartupOutcome::Absent(_),
                ..
            }
        ));
    }

    #[test]
    fn first_run_capability_rechecks_state_before_keychain_write() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let filesystem = FakeFileSystem::default();
        let mut secrets = TestSecrets::default();
        let initializer = StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone());
        let capability = match initializer
            .initialize_from_secrets(&secrets)
            .expect("key lookup")
        {
            SecretStartupOutcome::FirstRunNeedsKey(capability) => capability,
            _ => panic!("first run must issue a capability"),
        };
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .insert(path, b"state appeared".to_vec());
        let mut random = SequenceRandom(VecDeque::from([vec![0x55; 32]]));

        assert!(matches!(
            capability
                .create(&mut secrets, &mut random)
                .expect("capability recheck"),
            FirstRunCreationOutcome::StateAppeared
        ));
        assert_eq!(secrets.writes, 0);
        assert!(secrets.value.is_none());
    }

    #[test]
    fn post_write_state_race_returns_key_and_actual_startup_outcome() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let filesystem = FakeFileSystem::default();
        let generated_key = key_from_bytes(&[0x55; 32]).expect("generated key fixture");
        let appeared = encrypted(
            &Snapshot::new(1, b"appeared".to_vec()),
            &generated_key,
            0x77,
        );
        let mut secrets = TestSecrets {
            state_on_write: Some((filesystem.clone(), path.clone(), appeared)),
            ..TestSecrets::default()
        };
        let initializer = StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone());
        let capability = match initializer
            .initialize_from_secrets(&secrets)
            .expect("key lookup")
        {
            SecretStartupOutcome::FirstRunNeedsKey(capability) => capability,
            _ => panic!("first run must issue a capability"),
        };
        let mut random = SequenceRandom(VecDeque::from([vec![0x55; 32]]));

        assert!(matches!(
            capability
                .create(&mut secrets, &mut random)
                .expect("capability creation"),
            FirstRunCreationOutcome::KeyCreated {
                outcome: StartupOutcome::LoadedMustCancelEffects(_),
                ..
            }
        ));
        assert_eq!(secrets.writes, 1);
        assert!(secrets.value.is_some());
    }

    #[test]
    fn wrong_key_enters_recovery_and_preserves_ciphertext() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let wrong_key = key_from_bytes(&[0x99; 32]).expect("wrong key");
        let original = encrypted(&Snapshot::new(1, b"state".to_vec()), &key, 0x31);
        let filesystem = FakeFileSystem::default();
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .insert(path.clone(), original.clone());

        let initializer = StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone());
        assert!(matches!(
            initializer.initialize(&wrong_key),
            StartupOutcome::RecoveryRequired(RecoveryReason::AuthenticationFailed)
        ));
        assert_eq!(
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .get(&path),
            Some(&original)
        );
    }

    #[test]
    fn unreadable_or_unknown_store_is_preserved_and_blocks_overwrite() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let snapshot = Snapshot::new(1, b"state".to_vec());
        let future_snapshot = Snapshot::with_schema(99, 1, b"future state".to_vec());
        let mut unknown: serde_json::Value =
            serde_json::from_slice(&encrypted(&snapshot, &key, 0x31)).expect("fixture envelope");
        unknown["format_version"] = serde_json::json!(99);
        let cases = [
            (
                b"invalid ciphertext".to_vec(),
                RecoveryReason::AuthenticationFailed,
            ),
            (
                serde_json::to_vec(&unknown).expect("unknown envelope"),
                RecoveryReason::UnsupportedFormat,
            ),
            (
                encrypted(&future_snapshot, &key, 0x32),
                RecoveryReason::UnsupportedFormat,
            ),
        ];

        for (original, expected_reason) in cases {
            let filesystem = FakeFileSystem::default();
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .insert(path.clone(), original.clone());
            assert!(matches!(
                StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone())
                    .initialize(&key),
                StartupOutcome::RecoveryRequired(reason) if reason == expected_reason
            ));
            assert_eq!(
                filesystem
                    .0
                    .lock()
                    .expect("fake filesystem")
                    .files
                    .get(&path),
                Some(&original)
            );
        }
    }

    #[test]
    fn payload_bounds_accept_exact_limit_and_reject_plus_one_without_io() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let filesystem = FakeFileSystem::default();
        let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());
        let mut random = SequenceRandom(VecDeque::from([vec![0x21; 12]]));
        assert!(matches!(
            store.commit(
                Snapshot::new(1, vec![0x41; MAX_SNAPSHOT_PAYLOAD]),
                &key,
                &mut random
            ),
            CommitOutcome::Committed(_)
        ));

        let second_filesystem = FakeFileSystem::default();
        let mut second = AtomicStateStore::with_filesystem(path.clone(), second_filesystem.clone());
        let mut unused_random = SequenceRandom(VecDeque::new());
        assert_eq!(
            second.commit(
                Snapshot::new(1, vec![0x41; MAX_SNAPSHOT_PAYLOAD + 1]),
                &key,
                &mut unused_random
            ),
            CommitOutcome::Rejected(CommitRejection::PayloadTooLarge)
        );
        assert!(second_filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .operations
            .is_empty());
    }

    #[test]
    fn bounded_reader_rejects_oversized_json_and_ciphertext() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        for original in [
            vec![b' '; MAX_ENVELOPE_BYTES + 1],
            format!(
                r#"{{"format_version":1,"algorithm":"AES-256-GCM","key_identifier":"otpbar-local-state-v1","associated_data_version":1,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":"{}"}}"#,
                "A".repeat(MAX_ENVELOPE_BYTES)
            )
            .into_bytes(),
        ] {
            let filesystem = FakeFileSystem::default();
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .insert(path.clone(), original.clone());
            assert!(matches!(
                StateStoreInitializer::with_filesystem(path.clone(), filesystem.clone())
                    .initialize(&key),
                StartupOutcome::RecoveryRequired(RecoveryReason::OversizedState)
            ));
            assert_eq!(
                filesystem
                    .0
                    .lock()
                    .expect("fake filesystem")
                    .files
                    .get(&path),
                Some(&original)
            );
        }
    }

    #[test]
    fn too_many_owned_temps_are_preserved_without_inspection() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap();
        let filesystem = FakeFileSystem::default();
        for sequence in 0..=MAX_OWNED_TEMPS {
            filesystem.0.lock().expect("fake filesystem").files.insert(
                path.parent()
                    .unwrap()
                    .join(format!(".{file_name}.123.{sequence}.tmp")),
                b"not inspected".to_vec(),
            );
        }
        assert!(matches!(
            StateStoreInitializer::with_filesystem(path, filesystem.clone())
                .initialize(&test_key()),
            StartupOutcome::RecoveryRequired(RecoveryReason::TooManyTemporaryFiles)
        ));
        assert_eq!(
            filesystem.0.lock().expect("fake filesystem").files.len(),
            MAX_OWNED_TEMPS + 1
        );
    }

    #[test]
    fn authoritative_identity_rejects_unlink_rollback_stale_and_same_revision_change() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let cases = [
            None,
            Some(Snapshot::new(1, b"rollback".to_vec())),
            Some(Snapshot::new(2, b"different payload".to_vec())),
            Some(Snapshot::new(3, b"stale future".to_vec())),
        ];
        for replacement in cases {
            let filesystem = FakeFileSystem::default();
            let mut store = store_with_prior(
                &path,
                &filesystem,
                &key,
                &Snapshot::new(2, b"authoritative".to_vec()),
            );
            {
                let mut state = filesystem.0.lock().expect("fake filesystem");
                match replacement.as_ref() {
                    Some(snapshot) => {
                        state
                            .files
                            .insert(path.clone(), encrypted(snapshot, &key, 0x44));
                    }
                    None => {
                        state.files.remove(&path);
                    }
                }
            }
            let before = filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .get(&path)
                .cloned();
            let mut random = SequenceRandom(VecDeque::from([vec![0x45; 12]]));
            let outcome = store.commit(Snapshot::new(3, b"next".to_vec()), &key, &mut random);
            assert!(matches!(outcome, CommitOutcome::RecoveryRequired(_)));
            assert_eq!(
                filesystem
                    .0
                    .lock()
                    .expect("fake filesystem")
                    .files
                    .get(&path)
                    .cloned(),
                before
            );
            assert_eq!(
                store.commit(Snapshot::new(3, b"retry".to_vec()), &key, &mut random),
                CommitOutcome::Blocked
            );
        }
    }

    #[test]
    fn revision_must_be_exactly_next_and_cannot_overflow() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let filesystem = FakeFileSystem::default();
        let mut store = store_with_prior(
            &path,
            &filesystem,
            &key,
            &Snapshot::new(1, b"authoritative".to_vec()),
        );
        let before = filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .get(&path)
            .cloned();
        let mut random = SequenceRandom(VecDeque::new());
        for revision in [0, 1, 3] {
            assert_eq!(
                store.commit(
                    Snapshot::new(revision, b"invalid".to_vec()),
                    &key,
                    &mut random
                ),
                CommitOutcome::Rejected(CommitRejection::RevisionNotNext)
            );
        }
        assert_eq!(
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .get(&path)
                .cloned(),
            before
        );

        let overflow_filesystem = FakeFileSystem::default();
        let mut overflow = store_with_prior(
            &path,
            &overflow_filesystem,
            &key,
            &Snapshot::new(u64::MAX, b"max".to_vec()),
        );
        assert_eq!(
            overflow.commit(
                Snapshot::new(u64::MAX, b"again".to_vec()),
                &key,
                &mut random
            ),
            CommitOutcome::Rejected(CommitRejection::RevisionOverflow)
        );
    }

    #[test]
    fn production_nofollow_rejects_destination_and_owned_temp_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let path = directory.0.join("otpbar-state.json");
        let target = directory.0.join("target");
        fs::write(&target, b"do not follow").expect("target");
        symlink(&target, &path).expect("destination symlink");
        let key = test_key();
        assert!(matches!(
            StateStoreInitializer::open(path.clone())
                .expect("lock")
                .initialize(&key),
            StartupOutcome::RecoveryRequired(RecoveryReason::UnsafeEntryType)
        ));
        assert_eq!(fs::read(&target).unwrap(), b"do not follow");
        fs::remove_file(&path).unwrap();

        let snapshot = Snapshot::new(1, b"authoritative".to_vec());
        fs::write(&path, encrypted(&snapshot, &key, 0x31)).unwrap();
        let temp = directory.0.join(".otpbar-state.json.123.456.tmp");
        symlink(&target, &temp).unwrap();
        assert!(matches!(
            StateStoreInitializer::open(path.clone())
                .expect("lock")
                .initialize(&key),
            StartupOutcome::RecoveryRequired(RecoveryReason::InvalidTemporaryState)
        ));
        assert!(temp.is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"do not follow");
    }

    #[test]
    fn exclusive_lock_blocks_second_process_without_sleeping() {
        const CHILD_ENV: &str = "OTPBAR_STATE_LOCK_CHILD";
        const PATH_ENV: &str = "OTPBAR_STATE_LOCK_PATH";
        if std::env::var_os(CHILD_ENV).is_some() {
            let path = PathBuf::from(std::env::var_os(PATH_ENV).expect("child path"));
            let _owner = StateStoreInitializer::open(path).expect("child lock");
            println!("LOCK_READY");
            std::io::stdout().flush().unwrap();
            let mut release = String::new();
            std::io::stdin().read_line(&mut release).unwrap();
            return;
        }

        let directory = TestDirectory::new();
        let path = directory.0.join("otpbar-state.json");
        let temp = directory.0.join(".otpbar-state.json.123.456.tmp");
        fs::write(&temp, b"must remain").unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "state_store::io::tests::exclusive_lock_blocks_second_process_without_sleeping",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .env(PATH_ENV, &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn lock holder");
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert!(stdout.read_line(&mut line).unwrap() > 0);
            if line.contains("LOCK_READY") {
                break;
            }
        }
        assert!(matches!(
            StateStoreInitializer::open(path.clone()),
            Err(OpenError::StoreInUse)
        ));
        assert_eq!(fs::read(&temp).unwrap(), b"must remain");
        child.stdin.take().unwrap().write_all(b"release\n").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(StateStoreInitializer::open(path).is_ok());
    }

    #[test]
    fn production_filesystem_roundtrip_uses_owner_only_file_permissions() {
        let directory = TestDirectory::new();
        let path = directory.0.join("otpbar-state.json");
        let key = test_key();
        let mut store = match StateStoreInitializer::open(path.clone())
            .expect("acquire test store")
            .initialize(&key)
        {
            StartupOutcome::Absent(store) => store,
            other => panic!("unexpected startup outcome: {other:?}"),
        };
        let snapshot = Snapshot::new(1, b"sensitive state".to_vec());
        let expected = SnapshotIdentity::from_snapshot(&snapshot);
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        assert_eq!(
            store.commit(snapshot, &key, &mut random),
            CommitOutcome::Committed(expected)
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let loaded = store.load(&key).expect("load state").expect("snapshot");
        assert_eq!(loaded.revision(), 1);
        assert_eq!(loaded.payload(), b"sensitive state");
        assert_eq!(
            fs::read_dir(&directory.0)
                .expect("read test directory")
                .count(),
            2
        );
    }
}
