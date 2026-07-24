use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};

use crate::ports::RandomSource;

use super::crypto::{decode, decrypt, encode, encrypt, CryptoError, Snapshot, StateKey};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

trait FileSystem: Send + Sync {
    fn write_temp(&self, destination: &Path, bytes: &[u8]) -> io::Result<PathBuf>;
    fn sync_temp(&self, temp: &Path) -> io::Result<()>;
    fn replace(&self, temp: &Path, destination: &Path) -> io::Result<()>;
    fn sync_parent(&self, destination: &Path) -> io::Result<()>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn remove_temp(&self, path: &Path);
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

    fn remove_temp(&self, path: &Path) {
        let _ = fs::remove_file(path);
    }
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

/// Startup classification after a process exited with an unresolved barrier.
#[derive(PartialEq, Eq)]
pub enum RestartOutcome {
    /// The authenticated prior snapshot survived; the proposal may be retried.
    Prior(Snapshot),
    /// No file survived and there was no prior snapshot.
    PriorAbsent,
    /// The authenticated proposed snapshot survived; automatic effects must be canceled.
    NewMustCancelEffects(Snapshot),
    /// State was unreadable or did not match an allowed revision.
    RecoveryRequired(RecoveryReason),
}

impl std::fmt::Debug for RestartOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prior(snapshot) => formatter
                .debug_tuple("Prior")
                .field(&snapshot.revision())
                .finish(),
            Self::PriorAbsent => formatter.write_str("PriorAbsent"),
            Self::NewMustCancelEffects(snapshot) => formatter
                .debug_tuple("NewMustCancelEffects")
                .field(&snapshot.revision())
                .finish(),
            Self::RecoveryRequired(reason) => formatter
                .debug_tuple("RecoveryRequired")
                .field(reason)
                .finish(),
        }
    }
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

impl AtomicStateStore {
    /// Opens a production state store at an explicit application-data path.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            filesystem: Box::new(ProductionFileSystem),
            phase: StorePhase::Ready,
        }
    }

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
            self.filesystem.remove_temp(&temp);
            return CommitOutcome::Uncommitted;
        }
        if self.filesystem.replace(&temp, &self.path).is_err() {
            self.filesystem.remove_temp(&temp);
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

    /// Classifies whichever authenticated revision survived a crash before barrier retry.
    pub fn recover_after_restart(
        &mut self,
        key: &StateKey,
        prior: Option<SnapshotIdentity>,
        expected_new: SnapshotIdentity,
    ) -> RestartOutcome {
        let snapshot = match self.read_authenticated(key) {
            Ok(snapshot) => snapshot,
            Err(RecoveryReason::Missing) if prior.is_none() => return RestartOutcome::PriorAbsent,
            Err(reason) => {
                self.phase = StorePhase::Recovery(reason);
                return RestartOutcome::RecoveryRequired(reason);
            }
        };
        let actual = SnapshotIdentity::from_snapshot(&snapshot);
        if actual == expected_new {
            RestartOutcome::NewMustCancelEffects(snapshot)
        } else if prior == Some(actual) {
            RestartOutcome::Prior(snapshot)
        } else {
            self.phase = StorePhase::Recovery(RecoveryReason::UnexpectedSnapshot);
            RestartOutcome::RecoveryRequired(RecoveryReason::UnexpectedSnapshot)
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

fn map_crypto_error(error: CryptoError) -> RecoveryReason {
    match error {
        CryptoError::UnsupportedFormat => RecoveryReason::UnsupportedFormat,
        CryptoError::AuthenticationFailed
        | CryptoError::Encoding
        | CryptoError::InvalidStoredKey
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
        ports::RandomSource,
        state_store::crypto::{encode, encrypt, key_from_bytes, Snapshot, StateKey},
    };

    use super::{
        AtomicStateStore, BarrierRetryOutcome, CommitOutcome, FileSystem, RecoveryReason,
        RestartOutcome, SnapshotIdentity, StoreAccessError,
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
            let temp = destination.with_extension("test-tmp");
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

        fn remove_temp(&self, path: &Path) {
            self.0.lock().expect("fake filesystem").files.remove(path);
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
    fn crash_before_retry_accepts_only_authenticated_prior_or_new() {
        let path = PathBuf::from("/state/otpbar-state.json");
        let key = test_key();
        let prior = Snapshot::new(1, b"prior".to_vec());
        let new = Snapshot::new(2, b"new".to_vec());
        let prior_identity = SnapshotIdentity::from_snapshot(&prior);
        let new_identity = SnapshotIdentity::from_snapshot(&new);
        let cases = [
            (
                encrypted(&prior, &key, 0x31),
                RestartOutcome::Prior(prior.clone()),
            ),
            (
                encrypted(&new, &key, 0x32),
                RestartOutcome::NewMustCancelEffects(new.clone()),
            ),
            (
                b"unreadable".to_vec(),
                RestartOutcome::RecoveryRequired(RecoveryReason::AuthenticationFailed),
            ),
        ];

        for (survivor, expected) in cases {
            let filesystem = FakeFileSystem::default();
            filesystem
                .0
                .lock()
                .expect("fake filesystem")
                .files
                .insert(path.clone(), survivor);
            let mut restarted = AtomicStateStore::with_filesystem(path.clone(), filesystem.clone());

            assert_eq!(
                restarted.recover_after_restart(&key, Some(prior_identity), new_identity),
                expected
            );
        }
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
        let mut store = AtomicStateStore::new(path.clone());
        let key = test_key();
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
