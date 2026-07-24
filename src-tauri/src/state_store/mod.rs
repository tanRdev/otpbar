//! Authenticated, crash-safe local state persistence.
//!
//! Startup and live operation are deliberately separate:
//!
//! 1. [`StateStoreInitializer::initialize_from_secrets`] reads an existing
//!    application-readable Keychain key without creating one.
//! 2. Existing ciphertext with no key enters recovery. Only an opaque
//!    [`FirstRunKeyCapability`] can create a key, and it rechecks that no state
//!    appeared before writing Keychain.
//! 3. Every authenticated startup snapshot is returned as
//!    [`StartupOutcome::LoadedMustCancelEffects`]. The snapshot is available
//!    for canceling pending/claimed effect metadata, while the live store is
//!    withheld until
//!    [`LoadedStartup::into_store_for_effect_cancellation`] begins that
//!    recovery step. The returned store may only durably commit cancellation;
//!    intake and effects remain stopped until that commit succeeds. Task 20
//!    owns this gate and its literal subprocess crash coverage.
//! 4. A live store that reaches the post-replace durability barrier exposes no
//!    read path. [`AtomicStateStore::retry_barrier`] is its only resolving
//!    operation, and authenticated expected-new verification happens only
//!    after a parent-directory fsync succeeds.
//!
//! The Keychain key is application-readable. This module makes no Secure
//! Enclave or non-exportability claim.
//!
//! The raw key creator is intentionally not public:
//!
//! ```compile_fail
//! use otpbar::state_store::create_first_run_key;
//! ```

mod crypto;
mod io;
mod keychain;

pub use crypto::{load_existing_key, CryptoError, Snapshot, StateKey, SystemRandom};
pub use io::{
    AtomicStateStore, BarrierRetryOutcome, CommitOutcome, FirstRunCreationOutcome,
    FirstRunKeyCapability, LoadedStartup, RecoveryReason, SecretStartupOutcome, SnapshotIdentity,
    StartupOutcome, StateStoreInitializer, StoreAccessError,
};
pub use keychain::KeychainSecretStore;
