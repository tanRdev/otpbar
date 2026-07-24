//! Authenticated, crash-safe local state persistence.

mod crypto;
mod io;
mod keychain;

pub use crypto::{load_or_create_key, CryptoError, Snapshot, StateKey, SystemRandom};
pub use io::{
    AtomicStateStore, BarrierRetryOutcome, CommitOutcome, RecoveryReason, RestartOutcome,
    SnapshotIdentity, StoreAccessError,
};
pub use keychain::KeychainSecretStore;
