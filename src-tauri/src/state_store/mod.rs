//! Authenticated, crash-safe local state persistence.
//!
//! Startup and live operation are deliberately separate:
//!
//! 1. [`StateStoreInitializer::initialize_from_secrets`] reads an existing
//!    application-readable Keychain key without creating one.
//! 2. Existing ciphertext with no key enters recovery. Only
//!    [`create_first_run_key`] can create a key, after startup proved that no
//!    state exists.
//! 3. Every authenticated startup snapshot is returned as
//!    [`StartupOutcome::LoadedMustCancelEffects`]. The snapshot is available
//!    for canceling pending/claimed effect metadata, while the live store is
//!    withheld until
//!    [`LoadedStartup::into_store_after_canceling_effects`] acknowledges that
//!    recovery step.
//! 4. A live store that reaches the post-replace durability barrier exposes no
//!    read path. [`AtomicStateStore::retry_barrier`] is its only resolving
//!    operation, and authenticated expected-new verification happens only
//!    after a parent-directory fsync succeeds.
//!
//! The Keychain key is application-readable. This module makes no Secure
//! Enclave or non-exportability claim.

mod crypto;
mod io;
mod keychain;

pub use crypto::{
    create_first_run_key, load_existing_key, CryptoError, Snapshot, StateKey, SystemRandom,
};
pub use io::{
    AtomicStateStore, BarrierRetryOutcome, CommitOutcome, LoadedStartup, RecoveryReason,
    SecretStartupOutcome, SnapshotIdentity, StartupOutcome, StateStoreInitializer,
    StoreAccessError,
};
pub use keychain::KeychainSecretStore;
