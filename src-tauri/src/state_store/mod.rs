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
//!    withheld until the crate-private effect-cancellation transition begins
//!    that recovery step. The returned store may only durably commit
//!    cancellation; intake and effects remain stopped until that commit
//!    succeeds. Task 20 owns this gate and its literal subprocess crash
//!    coverage.
//! 4. A live store that reaches the post-replace durability barrier exposes no
//!    read path. [`AtomicStateStore::retry_barrier`] is its only resolving
//!    operation, and authenticated expected-new verification happens only
//!    after a parent-directory fsync succeeds.
//!
//! The Keychain key is application-readable. This module zeroizes owned key
//! bytes, plaintext buffers, and the AES key schedule where its dependencies
//! support that behavior; it makes no claim about every derived
//! authentication primitive. It also makes no Secure Enclave or
//! non-exportability claim.
//!
//! The raw key creator is intentionally not public:
//!
//! ```compile_fail
//! use otpbar::state_store::create_first_run_key;
//! ```
//!
//! Loaded startup state cannot be publicly activated before Task 20 adds the
//! typed durable cancellation transition:
//!
//! ```compile_fail
//! use otpbar::state_store::LoadedStartup;
//! fn bypass(loaded: LoadedStartup) {
//!     let _store = loaded.into_store_for_effect_cancellation();
//! }
//! ```

mod crypto;
mod io;
mod keychain;

pub use crypto::{CryptoError, Snapshot, StateKey, SystemRandom};
pub use io::{
    AtomicStateStore, BarrierRetryOutcome, CommitOutcome, CommitRejection, FirstRunCreationOutcome,
    FirstRunKeyCapability, LoadedStartup, OpenError, RecoveryReason, SecretStartupOutcome,
    SnapshotIdentity, StartupOutcome, StateStoreInitializer, StoreAccessError, MAX_ENVELOPE_BYTES,
    MAX_OWNED_TEMPS, MAX_SNAPSHOT_PAYLOAD,
};
pub use keychain::KeychainSecretStore;
