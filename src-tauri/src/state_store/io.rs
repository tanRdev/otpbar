use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};

use crate::ports::{RandomSource, SecretStore};

use super::crypto::{
    create_first_run_key, decode, decrypt, encode, encrypt, load_existing_key, CryptoError,
    Snapshot, StateKey,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

trait FileSystem: Send + Sync {
    fn write_temp(&self, destination: &Path, bytes: &[u8]) -> io::Result<PathBuf>;
    fn sync_temp(&self, temp: &Path) -> io::Result<()>;
    fn replace(&self, temp: &Path, destination: &Path) -> io::Result<()>;
    fn sync_parent(&self, destination: &Path) -> io::Result<()>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn remove_temp(&self, path: &Path) -> io::Result<()>;
    fn discover_owned_temps(&self, destination: &Path) -> io::Result<Vec<PathBuf>>;
    fn exists(&self, path: &Path) -> bool;
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
        OpenOptions::new().write(true).open(temp)?.sync_all()
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

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
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
            if entry.file_type()?.is_file()
                && is_owned_temp_name(destination, &entry.file_name().to_string_lossy())
            {
                owned.push(entry.path());
            }
        }
        owned.sort();
        Ok(owned)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
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
    pub fn into_store_for_effect_cancellation(self) -> AtomicStateStore {
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
        if self.initializer.has_any_state() {
            return Ok(FirstRunCreationOutcome::StateAppeared);
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
    Ready,
    BarrierPending(SnapshotIdentity),
    Recovery(RecoveryReason),
}

/// Stateful encrypted atomic snapshot store.
pub struct AtomicStateStore {
    path: PathBuf,
    filesystem: Box<dyn FileSystem>,
    phase: StorePhase,
}

/// One-way startup path, distinct from operations on a live store.
pub struct StateStoreInitializer {
    path: PathBuf,
    filesystem: Box<dyn FileSystem>,
}

impl StateStoreInitializer {
    /// Creates a production startup initializer for one explicit state path.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            filesystem: Box::new(ProductionFileSystem),
        }
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
            None if self.has_any_state() => Ok(SecretStartupOutcome::RecoveryRequired(
                RecoveryReason::MissingKey,
            )),
            None => Ok(SecretStartupOutcome::FirstRunNeedsKey(
                FirstRunKeyCapability { initializer: self },
            )),
        }
    }

    /// Authenticates startup state and consumes the initializer.
    pub fn initialize(self, key: &StateKey) -> StartupOutcome {
        initialize_store(self.path, self.filesystem, key)
    }

    fn has_any_state(&self) -> bool {
        self.filesystem.exists(&self.path)
            || self
                .filesystem
                .discover_owned_temps(&self.path)
                .map(|temps| !temps.is_empty())
                .unwrap_or(true)
    }

    #[cfg(test)]
    fn with_filesystem(path: PathBuf, filesystem: impl FileSystem + 'static) -> Self {
        Self {
            path,
            filesystem: Box::new(filesystem),
        }
    }
}

impl AtomicStateStore {
    #[cfg(test)]
    fn with_filesystem(path: PathBuf, filesystem: impl FileSystem + 'static) -> Self {
        Self {
            path,
            filesystem: Box::new(filesystem),
            phase: StorePhase::Ready,
        }
    }

    /// Writes, syncs, replaces, crosses the directory barrier, and verifies expected-new.
    pub fn commit(
        &mut self,
        snapshot: Snapshot,
        key: &StateKey,
        random: &mut impl RandomSource,
    ) -> CommitOutcome {
        if !matches!(self.phase, StorePhase::Ready) {
            return CommitOutcome::Blocked;
        }

        let expected = SnapshotIdentity::from_snapshot(&snapshot);
        let bytes = match encrypt(&snapshot, key, random).and_then(|envelope| encode(&envelope)) {
            Ok(bytes) => bytes,
            Err(_) => return CommitOutcome::Uncommitted,
        };
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
            StorePhase::BarrierPending(_) => return Err(StoreAccessError::BarrierPending),
            StorePhase::Recovery(reason) => {
                return Err(StoreAccessError::RecoveryRequired(reason));
            }
            StorePhase::Ready => {}
        }
        match self.read_authenticated(key) {
            Ok(snapshot) => Ok(Some(snapshot)),
            Err(RecoveryReason::Missing) => Ok(None),
            Err(reason) => {
                self.phase = StorePhase::Recovery(reason);
                Err(StoreAccessError::RecoveryRequired(reason))
            }
        }
    }

    fn resolve_expected(&mut self, key: &StateKey, expected: SnapshotIdentity) -> CommitOutcome {
        match self.read_authenticated(key) {
            Ok(snapshot) if SnapshotIdentity::from_snapshot(&snapshot) == expected => {
                self.phase = StorePhase::Ready;
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
        let bytes = self.filesystem.read(&self.path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                RecoveryReason::Missing
            } else {
                RecoveryReason::ReadFailed
            }
        })?;
        let envelope = decode(&bytes).map_err(map_crypto_error)?;
        decrypt(&envelope, key).map_err(map_crypto_error)
    }
}

fn initialize_store(
    path: PathBuf,
    filesystem: Box<dyn FileSystem>,
    key: &StateKey,
) -> StartupOutcome {
    let store = AtomicStateStore {
        path,
        filesystem,
        phase: StorePhase::Ready,
    };
    let temps = match store.filesystem.discover_owned_temps(&store.path) {
        Ok(temps) => temps,
        Err(_) => return StartupOutcome::RecoveryRequired(RecoveryReason::ReadFailed),
    };
    for temp in temps {
        let valid = store
            .filesystem
            .read(&temp)
            .map_err(|_| RecoveryReason::InvalidTemporaryState)
            .and_then(|bytes| decode(&bytes).map_err(|_| RecoveryReason::InvalidTemporaryState))
            .and_then(|envelope| {
                decrypt(&envelope, key).map_err(|_| RecoveryReason::InvalidTemporaryState)
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
        Ok(snapshot) => StartupOutcome::LoadedMustCancelEffects(LoadedStartup { store, snapshot }),
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
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
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
        is_owned_temp_name, AtomicStateStore, BarrierRetryOutcome, CommitOutcome, FileSystem,
        FirstRunCreationOutcome, RecoveryReason, SecretStartupOutcome, SnapshotIdentity,
        StartupOutcome, StateStoreInitializer, StoreAccessError,
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

        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            let mut state = self.0.lock().expect("fake filesystem");
            state.operations.push("read");
            state.read_count += 1;
            match state.read_results.pop_front().unwrap_or(FakeRead::Actual) {
                FakeRead::Actual => state
                    .files
                    .get(path)
                    .cloned()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing")),
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

        fn exists(&self, path: &Path) -> bool {
            self.0
                .lock()
                .expect("fake filesystem")
                .files
                .contains_key(path)
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

    #[test]
    fn failure_before_replace_is_uncommitted_and_preserves_prior_snapshot() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .insert(path.clone(), b"prior ciphertext".to_vec());
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .fail_temp_write = true;
        let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());
        let key = test_key();
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        let outcome = store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random);

        assert_eq!(outcome, CommitOutcome::Uncommitted);
        let state = filesystem.0.lock().expect("fake filesystem");
        assert_eq!(
            state.files.get(&path).map(Vec::as_slice),
            Some(b"prior ciphertext".as_slice())
        );
        assert_eq!(state.read_count, 0);
    }

    #[test]
    fn random_source_failure_is_pre_replace_and_uncommitted() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        let original = b"prior ciphertext".to_vec();
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .insert(path.clone(), original.clone());
        let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());
        let key = test_key();
        let mut failing_random = SequenceRandom(VecDeque::new());

        assert_eq!(
            store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut failing_random),
            CommitOutcome::Uncommitted
        );
        let state = filesystem.0.lock().expect("fake filesystem");
        assert!(state.operations.is_empty());
        assert_eq!(state.files.get(&path), Some(&original));
    }

    #[test]
    fn replace_failure_is_uncommitted_and_removes_non_authoritative_temp() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        filesystem
            .0
            .lock()
            .expect("fake filesystem")
            .files
            .insert(path.clone(), b"prior ciphertext".to_vec());
        filesystem.0.lock().expect("fake filesystem").fail_replace = true;
        let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());
        let key = test_key();
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        let outcome = store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random);

        assert_eq!(outcome, CommitOutcome::Uncommitted);
        let state = filesystem.0.lock().expect("fake filesystem");
        assert_eq!(
            state.files.get(&path).map(Vec::as_slice),
            Some(b"prior ciphertext".as_slice())
        );
        assert_eq!(state.files.len(), 1);
        assert_eq!(state.read_count, 0);
    }

    #[test]
    fn temp_file_sync_failure_prevents_replace_and_is_uncommitted() {
        let filesystem = FakeFileSystem::default();
        let path = PathBuf::from("/state/otpbar-state.json");
        {
            let mut state = filesystem.0.lock().expect("fake filesystem");
            state
                .files
                .insert(path.clone(), b"prior ciphertext".to_vec());
            state.fail_temp_sync = true;
        }
        let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());
        let key = test_key();
        let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));

        assert_eq!(
            store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random),
            CommitOutcome::Uncommitted
        );
        let state = filesystem.0.lock().expect("fake filesystem");
        assert_eq!(state.operations, ["write_temp", "sync_temp"]);
        assert_eq!(
            state.files.get(&path).map(Vec::as_slice),
            Some(b"prior ciphertext".as_slice())
        );
        assert_eq!(state.files.len(), 1);
        assert_eq!(state.read_count, 0);
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
            store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random),
            CommitOutcome::BarrierPending
        );
        assert!(matches!(
            store.load(&key),
            Err(StoreAccessError::BarrierPending)
        ));
        assert_eq!(
            store.commit(Snapshot::new(3, b"newer".to_vec()), &key, &mut random),
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
        let new = Snapshot::new(2, b"new".to_vec());
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
                store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random),
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
                store.commit(Snapshot::new(2, b"new".to_vec()), &key, &mut random),
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
            let mut store = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());

            assert!(matches!(
                store.load(&key),
                Err(StoreAccessError::RecoveryRequired(reason)) if reason == expected_reason
            ));
            let mut random = SequenceRandom(VecDeque::from([vec![0x22; 12]]));
            assert_eq!(
                store.commit(Snapshot::new(2, b"replacement".to_vec()), &key, &mut random),
                CommitOutcome::Blocked
            );
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
    fn production_filesystem_roundtrip_uses_owner_only_file_permissions() {
        let directory = TestDirectory::new();
        let path = directory.0.join("otpbar-state.json");
        let key = test_key();
        let mut store = match StateStoreInitializer::new(path.clone()).initialize(&key) {
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
            1
        );
    }
}
