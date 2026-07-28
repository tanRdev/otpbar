//! Pure, cancellable public-client Authorization attempt state.
//!
//! Transport adapters own loopback listeners, browser launches, token exchange,
//! and credential persistence. This module owns only the short-lived PKCE/state
//! material and the transitions that make an attempt safe to replace or cancel.

use std::{fmt, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{clock::Timestamp, ports::RandomSource};

const PKCE_RANDOM_BYTES: usize = 32;
const STATE_RANDOM_BYTES: usize = 32;

/// Opaque identifier for one Authorization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId(u64);

impl AttemptId {
    /// Returns the stable identifier used to associate a callback with its
    /// listener. It is operational metadata, not part of the public status.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The frozen section 4.2 public Authorization contract.
///
/// Attempt identifiers, deadlines, Authorization codes, PKCE material, and
/// callback state are deliberately absent from this serializable type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthorizationStatus {
    UnknownRestoring,
    Disconnected,
    Starting,
    AwaitingBrowser,
    Exchanging,
    Connected,
    Cancelled,
    Denied,
    CallbackInvalid,
    ConfigurationMissing,
    CredentialStoreUnavailable,
    RefreshRequired,
    Failed,
}

/// Stable, secret-free causes used to map adapter failures to public states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationFailure {
    CallbackInvalid,
    ExchangeFailed,
    ConfigurationMissing,
    CredentialStoreUnavailable,
    RefreshRequired,
    RandomUnavailable,
}

/// Error returned while preparing an Authorization attempt.
///
/// The random source's internal error is deliberately discarded because it can
/// contain platform details and must not become a public Authorization error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    RandomUnavailable,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomUnavailable => {
                formatter.write_str("Secure random data is temporarily unavailable.")
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

/// Outcome from consuming a callback for an Authorization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackOutcome {
    ExchangeReady,
    Denied,
    Failed,
    Invalid,
    TimedOut,
    Ignored,
}

/// Browser-facing public values generated for one attempt.
///
/// Callback state is intentionally not serializable or printable. A transport
/// adapter may read it only to construct the authorization request.
pub struct AuthorizationRequest {
    attempt_id: AttemptId,
    pkce_challenge: String,
    state: Zeroizing<String>,
}

impl AuthorizationRequest {
    /// Identifies the listener that must receive this request's callback.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the S256 PKCE challenge sent to the authorization server.
    pub fn pkce_challenge(&self) -> &str {
        &self.pkce_challenge
    }

    /// Returns the CSRF state placed in this request's URL.
    pub fn state(&self) -> &str {
        &self.state
    }
}

impl fmt::Debug for AuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("attempt_id", &self.attempt_id)
            .field("pkce_challenge", &"[redacted]")
            .field("state", &"[redacted]")
            .finish()
    }
}

/// Short-lived material an exchange adapter needs after a valid callback.
///
/// It borrows the core and cannot outlive its active attempt. It intentionally
/// has no serialization implementation and redacts the verifier in `Debug`.
pub struct ExchangeMaterial<'a> {
    attempt_id: AttemptId,
    pkce_verifier: &'a str,
}

impl ExchangeMaterial<'_> {
    /// Identifies the exchange's active Authorization attempt.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the PKCE verifier for the token exchange request only.
    pub fn pkce_verifier(&self) -> &str {
        self.pkce_verifier
    }
}

impl fmt::Debug for ExchangeMaterial<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExchangeMaterial")
            .field("attempt_id", &self.attempt_id)
            .field("pkce_verifier", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptPhase {
    Preparing,
    AwaitingCallback { deadline: Timestamp },
    Exchanging,
}

struct Attempt {
    id: AttemptId,
    phase: AttemptPhase,
    pkce_verifier: Zeroizing<String>,
    state: Zeroizing<[u8; STATE_RANDOM_BYTES]>,
}

/// One public-client Authorization attempt owner.
///
/// Calls are synchronous state transitions: no browser, listener, network, or
/// credential I/O occurs here. Adapters pass the current `AttemptId` so a
/// callback from a replaced listener cannot affect a newer attempt.
pub struct AuthorizationCore {
    status: AuthorizationStatus,
    callback_timeout: Duration,
    next_attempt_id: u64,
    active: Option<Attempt>,
}

impl AuthorizationCore {
    /// Creates a core in the startup restoration state. The callback timeout
    /// starts only after a listener binds and `await_callback` is called.
    pub fn new(callback_timeout: Duration) -> Self {
        Self {
            status: AuthorizationStatus::UnknownRestoring,
            callback_timeout,
            next_attempt_id: 1,
            active: None,
        }
    }

    /// Returns the safe, current public Authorization status.
    pub const fn status(&self) -> AuthorizationStatus {
        self.status
    }

    /// Completes startup restoration with usable credentials.
    pub fn restore_connected(&mut self) -> bool {
        self.complete_restoration(AuthorizationStatus::Connected)
    }

    /// Completes startup restoration without credentials.
    pub fn restore_disconnected(&mut self) -> bool {
        self.complete_restoration(AuthorizationStatus::Disconnected)
    }

    /// Completes startup restoration when credentials require renewed consent.
    pub fn restore_refresh_required(&mut self) -> bool {
        self.complete_restoration(AuthorizationStatus::RefreshRequired)
    }

    /// Completes startup restoration when public-client configuration is absent.
    pub fn restore_configuration_missing(&mut self) -> bool {
        self.complete_restoration(AuthorizationStatus::ConfigurationMissing)
    }

    /// Completes startup restoration when credentials cannot be read.
    pub fn restore_credential_store_unavailable(&mut self) -> bool {
        self.complete_restoration(AuthorizationStatus::CredentialStoreUnavailable)
    }

    /// Completes startup restoration with a safe generic failure.
    pub fn restore_failed(&mut self) -> bool {
        self.complete_restoration(AuthorizationStatus::Failed)
    }

    /// Generates fresh public-client request material and enters `starting`.
    /// Starting another attempt drops the previous verifier/state and invalidates
    /// its listener identifier.
    pub fn prepare(
        &mut self,
        random: &mut impl RandomSource,
    ) -> Result<AuthorizationRequest, AuthorizationError> {
        self.active = None;

        let id = AttemptId(self.next_id());
        let (pkce_verifier, pkce_challenge, state, encoded_state) =
            match generate_request_material(random) {
                Ok(material) => material,
                Err(()) => {
                    self.status = AuthorizationStatus::Failed;
                    return Err(AuthorizationError::RandomUnavailable);
                }
            };

        self.active = Some(Attempt {
            id,
            phase: AttemptPhase::Preparing,
            pkce_verifier,
            state,
        });
        self.status = AuthorizationStatus::Starting;

        Ok(AuthorizationRequest {
            attempt_id: id,
            pkce_challenge,
            state: encoded_state,
        })
    }

    /// Marks the matching, already-bound loopback listener ready and starts its
    /// deadline. A superseded listener is ignored.
    pub fn await_callback(&mut self, attempt_id: AttemptId, now: Timestamp) -> bool {
        let Some(active) = self.active.as_mut() else {
            return false;
        };
        if active.id != attempt_id || active.phase != AttemptPhase::Preparing {
            return false;
        }

        active.phase = AttemptPhase::AwaitingCallback {
            deadline: now
                .checked_add(self.callback_timeout)
                .unwrap_or(Timestamp::from_unix_millis(i64::MAX)),
        };
        self.status = AuthorizationStatus::AwaitingBrowser;
        true
    }

    /// Validates and consumes one success callback.
    ///
    /// `now` is authoritative: a callback at or after its deadline times out
    /// even if no separate timeout tick has run.
    pub fn receive_callback(
        &mut self,
        attempt_id: AttemptId,
        received_state: &str,
        now: Timestamp,
    ) -> CallbackOutcome {
        if let Err(outcome) = self.validate_terminal_callback(attempt_id, received_state, now) {
            return outcome;
        }

        self.active
            .as_mut()
            .expect("validated callback must have an active attempt")
            .phase = AttemptPhase::Exchanging;
        self.status = AuthorizationStatus::Exchanging;
        CallbackOutcome::ExchangeReady
    }

    /// Validates and consumes one provider denial callback.
    pub fn deny_callback(
        &mut self,
        attempt_id: AttemptId,
        received_state: &str,
        now: Timestamp,
    ) -> CallbackOutcome {
        if let Err(outcome) = self.validate_terminal_callback(attempt_id, received_state, now) {
            return outcome;
        }

        self.active = None;
        self.status = AuthorizationStatus::Denied;
        CallbackOutcome::Denied
    }

    /// Validates and consumes one non-denial provider error callback.
    pub fn error_callback(
        &mut self,
        attempt_id: AttemptId,
        received_state: &str,
        now: Timestamp,
    ) -> CallbackOutcome {
        if let Err(outcome) = self.validate_terminal_callback(attempt_id, received_state, now) {
            return outcome;
        }

        self.active = None;
        self.status = AuthorizationStatus::Failed;
        CallbackOutcome::Failed
    }

    /// Returns exchange-only PKCE material while the matching attempt is active.
    pub fn exchange_material(&self, attempt_id: AttemptId) -> Option<ExchangeMaterial<'_>> {
        let active = self.active.as_ref()?;
        (active.id == attempt_id && active.phase == AttemptPhase::Exchanging).then_some(
            ExchangeMaterial {
                attempt_id,
                pkce_verifier: &active.pkce_verifier,
            },
        )
    }

    /// Completes a successful token exchange for the current attempt.
    pub fn exchange_succeeded(&mut self, attempt_id: AttemptId) -> bool {
        if !self.is_exchanging(attempt_id) {
            return false;
        }
        self.active = None;
        self.status = AuthorizationStatus::Connected;
        true
    }

    /// Completes a failed token exchange for the current attempt.
    pub fn exchange_failed(
        &mut self,
        attempt_id: AttemptId,
        failure: AuthorizationFailure,
    ) -> bool {
        if !self.is_exchanging(attempt_id) {
            return false;
        }
        self.active = None;
        self.status = failure.public_status();
        true
    }

    /// Moves an awaiting callback past its deadline into the generic public
    /// failure state.
    pub fn timeout_if_due(&mut self, now: Timestamp) -> bool {
        let due = self.active.as_ref().is_some_and(|active| {
            matches!(
                active.phase,
                AttemptPhase::AwaitingCallback { deadline } if now >= deadline
            )
        });
        if due {
            self.active = None;
            self.status = AuthorizationStatus::Failed;
        }
        due
    }

    /// Cancels an in-progress Authorization attempt. Terminal states are left
    /// unchanged so cancellation is idempotent.
    pub fn cancel(&mut self) -> bool {
        if self.active.is_none() {
            return false;
        }
        self.active = None;
        self.status = AuthorizationStatus::Cancelled;
        true
    }

    /// Clears transient state and re-enters startup restoration.
    pub fn restart(&mut self) {
        self.active = None;
        self.status = AuthorizationStatus::UnknownRestoring;
    }

    /// Ends Authorization locally. It is intentionally separate from History
    /// deletion and is idempotent.
    pub fn disconnect(&mut self) {
        self.active = None;
        self.status = AuthorizationStatus::Disconnected;
    }

    fn complete_restoration(&mut self, status: AuthorizationStatus) -> bool {
        if self.status != AuthorizationStatus::UnknownRestoring {
            return false;
        }
        self.status = status;
        true
    }

    fn validate_terminal_callback(
        &mut self,
        attempt_id: AttemptId,
        received_state: &str,
        now: Timestamp,
    ) -> Result<(), CallbackOutcome> {
        let Some(active) = self.active.as_ref() else {
            return Err(CallbackOutcome::Ignored);
        };
        let AttemptPhase::AwaitingCallback { deadline } = active.phase else {
            return Err(CallbackOutcome::Ignored);
        };
        if active.id != attempt_id {
            return Err(CallbackOutcome::Ignored);
        }
        if now >= deadline {
            self.active = None;
            self.status = AuthorizationStatus::Failed;
            return Err(CallbackOutcome::TimedOut);
        }
        if !state_matches(&active.state, received_state) {
            self.active = None;
            self.status = AuthorizationStatus::CallbackInvalid;
            return Err(CallbackOutcome::Invalid);
        }
        Ok(())
    }

    fn is_exchanging(&self, attempt_id: AttemptId) -> bool {
        self.active.as_ref().is_some_and(|active| {
            active.id == attempt_id && active.phase == AttemptPhase::Exchanging
        })
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_attempt_id;
        self.next_attempt_id = self.next_attempt_id.wrapping_add(1);
        if self.next_attempt_id == 0 {
            self.next_attempt_id = 1;
        }
        id
    }
}

impl AuthorizationFailure {
    const fn public_status(self) -> AuthorizationStatus {
        match self {
            Self::CallbackInvalid => AuthorizationStatus::CallbackInvalid,
            Self::ConfigurationMissing => AuthorizationStatus::ConfigurationMissing,
            Self::CredentialStoreUnavailable => AuthorizationStatus::CredentialStoreUnavailable,
            Self::RefreshRequired => AuthorizationStatus::RefreshRequired,
            Self::ExchangeFailed | Self::RandomUnavailable => AuthorizationStatus::Failed,
        }
    }
}

impl Default for AuthorizationCore {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

impl fmt::Debug for AuthorizationCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCore")
            .field("status", &self.status)
            .field("callback_timeout", &self.callback_timeout)
            .field("has_active_attempt", &self.active.is_some())
            .finish()
    }
}

type RequestMaterial = (
    Zeroizing<String>,
    String,
    Zeroizing<[u8; STATE_RANDOM_BYTES]>,
    Zeroizing<String>,
);

fn generate_request_material(random: &mut impl RandomSource) -> Result<RequestMaterial, ()> {
    let mut verifier_bytes = [0_u8; PKCE_RANDOM_BYTES];
    random.fill_bytes(&mut verifier_bytes).map_err(|_| ())?;
    let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier_bytes));
    verifier_bytes.zeroize();

    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    let mut state = Zeroizing::new([0_u8; STATE_RANDOM_BYTES]);
    random.fill_bytes(state.as_mut()).map_err(|_| ())?;
    let encoded_state = Zeroizing::new(URL_SAFE_NO_PAD.encode(state.as_ref()));

    Ok((verifier, challenge, state, encoded_state))
}

/// Decodes exactly one unpadded base64url 256-bit state and compares it with a
/// maintained constant-time primitive over fixed-size byte arrays.
fn state_matches(expected: &[u8; STATE_RANDOM_BYTES], received: &str) -> bool {
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(received) else {
        return false;
    };
    let decoded = Zeroizing::new(decoded);
    let Ok(received) = <&[u8; STATE_RANDOM_BYTES]>::try_from(decoded.as_slice()) else {
        return false;
    };
    bool::from(expected.ct_eq(received))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{domain::error::ErrorEnvelope, ports::RandomSource};

    const START: Timestamp = Timestamp::from_unix_millis(1_000);
    const BEFORE_DEADLINE: Timestamp = Timestamp::from_unix_millis(30_999);
    const DEADLINE: Timestamp = Timestamp::from_unix_millis(31_000);
    const AFTER_DEADLINE: Timestamp = Timestamp::from_unix_millis(31_001);

    #[derive(Default)]
    struct SequenceRandom {
        next: u8,
        fail: bool,
    }

    impl RandomSource for SequenceRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ErrorEnvelope> {
            if self.fail {
                return Err(ErrorEnvelope::new(
                    crate::domain::error::ErrorCode::StorageUnavailable,
                    crate::domain::error::UserMessage::LocalDataUnavailable,
                    true,
                ));
            }
            for byte in destination {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn core() -> AuthorizationCore {
        AuthorizationCore::new(Duration::from_secs(30))
    }

    fn awaiting(core: &mut AuthorizationCore, random: &mut SequenceRandom) -> AuthorizationRequest {
        let request = core.prepare(random).expect("entropy should be available");
        assert!(core.await_callback(request.attempt_id(), START));
        request
    }

    #[test]
    fn public_status_serialization_is_exactly_the_frozen_contract() {
        let cases = [
            (AuthorizationStatus::UnknownRestoring, "unknown_restoring"),
            (AuthorizationStatus::Disconnected, "disconnected"),
            (AuthorizationStatus::Starting, "starting"),
            (AuthorizationStatus::AwaitingBrowser, "awaiting_browser"),
            (AuthorizationStatus::Exchanging, "exchanging"),
            (AuthorizationStatus::Connected, "connected"),
            (AuthorizationStatus::Cancelled, "cancelled"),
            (AuthorizationStatus::Denied, "denied"),
            (AuthorizationStatus::CallbackInvalid, "callback_invalid"),
            (
                AuthorizationStatus::ConfigurationMissing,
                "configuration_missing",
            ),
            (
                AuthorizationStatus::CredentialStoreUnavailable,
                "credential_store_unavailable",
            ),
            (AuthorizationStatus::RefreshRequired, "refresh_required"),
            (AuthorizationStatus::Failed, "failed"),
        ];

        for (status, expected) in cases {
            assert_eq!(
                serde_json::to_value(status).expect("status serialization"),
                serde_json::json!({ "status": expected })
            );
        }
    }

    #[test]
    fn restoration_has_explicit_safe_outcomes() {
        let mut connected = core();
        assert_eq!(connected.status(), AuthorizationStatus::UnknownRestoring);
        assert!(connected.restore_connected());
        assert_eq!(connected.status(), AuthorizationStatus::Connected);
        assert!(!connected.restore_disconnected());

        let mut disconnected = core();
        assert!(disconnected.restore_disconnected());
        assert_eq!(disconnected.status(), AuthorizationStatus::Disconnected);

        let mut refresh = core();
        assert!(refresh.restore_refresh_required());
        assert_eq!(refresh.status(), AuthorizationStatus::RefreshRequired);

        let mut configuration = core();
        assert!(configuration.restore_configuration_missing());
        assert_eq!(
            configuration.status(),
            AuthorizationStatus::ConfigurationMissing
        );

        let mut credential_store = core();
        assert!(credential_store.restore_credential_store_unavailable());
        assert_eq!(
            credential_store.status(),
            AuthorizationStatus::CredentialStoreUnavailable
        );

        let mut failed = core();
        assert!(failed.restore_failed());
        assert_eq!(failed.status(), AuthorizationStatus::Failed);
    }

    #[test]
    fn preparation_makes_fresh_s256_pkce_and_256_bit_state() {
        let mut core = core();
        let mut random = SequenceRandom::default();

        let first = core.prepare(&mut random).expect("first request");
        let first_id = first.attempt_id();
        let first_state = first.state().to_owned();
        assert_eq!(core.status(), AuthorizationStatus::Starting);
        let second = core.prepare(&mut random).expect("second request");

        assert_ne!(first_id, second.attempt_id());
        assert_ne!(first_state, second.state());
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(second.state())
                .expect("base64url state")
                .len(),
            STATE_RANDOM_BYTES
        );
        let verifier = &core.active.as_ref().expect("active").pkce_verifier;
        assert_eq!(
            second.pkce_challenge(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
        );
    }

    #[test]
    fn success_callback_validates_state_before_exchange_and_is_single_use() {
        let mut core = core();
        let mut random = SequenceRandom::default();
        let request = awaiting(&mut core, &mut random);
        assert_eq!(core.status(), AuthorizationStatus::AwaitingBrowser);

        assert_eq!(
            core.receive_callback(request.attempt_id(), request.state(), BEFORE_DEADLINE),
            CallbackOutcome::ExchangeReady
        );
        assert_eq!(core.status(), AuthorizationStatus::Exchanging);
        let exchange = core
            .exchange_material(request.attempt_id())
            .expect("verifier for exchange");
        assert_eq!(exchange.attempt_id(), request.attempt_id());
        assert_eq!(
            core.receive_callback(request.attempt_id(), request.state(), BEFORE_DEADLINE),
            CallbackOutcome::Ignored
        );
        assert!(core.exchange_succeeded(request.attempt_id()));
        assert_eq!(core.status(), AuthorizationStatus::Connected);
    }

    #[test]
    fn malformed_wrong_length_and_mismatched_states_are_callback_invalid() {
        let mismatched = URL_SAFE_NO_PAD.encode([9_u8; STATE_RANDOM_BYTES]);
        for state in ["%", "AA", mismatched.as_str()] {
            let mut core = core();
            let mut random = SequenceRandom::default();
            let request = awaiting(&mut core, &mut random);

            assert_eq!(
                core.receive_callback(request.attempt_id(), state, BEFORE_DEADLINE),
                CallbackOutcome::Invalid
            );
            assert_eq!(core.status(), AuthorizationStatus::CallbackInvalid);
        }
    }

    #[test]
    fn denial_and_error_callbacks_validate_state_before_terminating() {
        let mut core = core();
        let mut random = SequenceRandom::default();
        let denied = awaiting(&mut core, &mut random);
        assert_eq!(
            core.deny_callback(denied.attempt_id(), denied.state(), BEFORE_DEADLINE),
            CallbackOutcome::Denied
        );
        assert_eq!(core.status(), AuthorizationStatus::Denied);

        let invalid_denial = awaiting(&mut core, &mut random);
        let mismatched = URL_SAFE_NO_PAD.encode([9_u8; STATE_RANDOM_BYTES]);
        assert_eq!(
            core.deny_callback(invalid_denial.attempt_id(), &mismatched, BEFORE_DEADLINE),
            CallbackOutcome::Invalid
        );
        assert_eq!(core.status(), AuthorizationStatus::CallbackInvalid);

        let provider_error = awaiting(&mut core, &mut random);
        assert_eq!(
            core.error_callback(
                provider_error.attempt_id(),
                provider_error.state(),
                BEFORE_DEADLINE
            ),
            CallbackOutcome::Failed
        );
        assert_eq!(core.status(), AuthorizationStatus::Failed);

        let invalid_error = awaiting(&mut core, &mut random);
        assert_eq!(
            core.error_callback(invalid_error.attempt_id(), "%", BEFORE_DEADLINE),
            CallbackOutcome::Invalid
        );
        assert_eq!(core.status(), AuthorizationStatus::CallbackInvalid);
    }

    #[test]
    fn callbacks_at_deadline_time_out_without_a_prior_timeout_tick() {
        let mut random = SequenceRandom::default();

        let mut success = core();
        let request = awaiting(&mut success, &mut random);
        assert_eq!(
            success.receive_callback(request.attempt_id(), request.state(), DEADLINE),
            CallbackOutcome::TimedOut
        );
        assert_eq!(success.status(), AuthorizationStatus::Failed);

        let mut denial = core();
        let request = awaiting(&mut denial, &mut random);
        assert_eq!(
            denial.deny_callback(request.attempt_id(), request.state(), AFTER_DEADLINE),
            CallbackOutcome::TimedOut
        );
        assert_eq!(denial.status(), AuthorizationStatus::Failed);

        let mut provider_error = core();
        let request = awaiting(&mut provider_error, &mut random);
        assert_eq!(
            provider_error.error_callback(request.attempt_id(), request.state(), DEADLINE),
            CallbackOutcome::TimedOut
        );
        assert_eq!(provider_error.status(), AuthorizationStatus::Failed);
    }

    #[test]
    fn cancellation_replacement_disconnect_and_restart_clear_attempts() {
        let mut core = core();
        let mut random = SequenceRandom::default();
        let first = awaiting(&mut core, &mut random);
        let second = core.prepare(&mut random).expect("replacement request");

        assert_eq!(
            core.receive_callback(first.attempt_id(), first.state(), BEFORE_DEADLINE),
            CallbackOutcome::Ignored
        );
        assert!(core.await_callback(second.attempt_id(), START));
        assert!(core.cancel());
        assert_eq!(core.status(), AuthorizationStatus::Cancelled);
        assert!(!core.cancel());

        let third = awaiting(&mut core, &mut random);
        core.disconnect();
        assert_eq!(core.status(), AuthorizationStatus::Disconnected);
        assert_eq!(
            core.receive_callback(third.attempt_id(), third.state(), BEFORE_DEADLINE),
            CallbackOutcome::Ignored
        );

        let fourth = core.prepare(&mut random).expect("clean reauthorization");
        core.restart();
        assert_eq!(core.status(), AuthorizationStatus::UnknownRestoring);
        assert_eq!(
            core.receive_callback(fourth.attempt_id(), fourth.state(), BEFORE_DEADLINE),
            CallbackOutcome::Ignored
        );
    }

    #[test]
    fn timeout_tick_and_exchange_failures_map_to_frozen_states() {
        let mut core = core();
        let mut random = SequenceRandom::default();
        let _request = awaiting(&mut core, &mut random);
        assert!(core.timeout_if_due(DEADLINE));
        assert_eq!(core.status(), AuthorizationStatus::Failed);

        for (failure, expected) in [
            (
                AuthorizationFailure::ConfigurationMissing,
                AuthorizationStatus::ConfigurationMissing,
            ),
            (
                AuthorizationFailure::CredentialStoreUnavailable,
                AuthorizationStatus::CredentialStoreUnavailable,
            ),
            (
                AuthorizationFailure::RefreshRequired,
                AuthorizationStatus::RefreshRequired,
            ),
            (
                AuthorizationFailure::CallbackInvalid,
                AuthorizationStatus::CallbackInvalid,
            ),
            (
                AuthorizationFailure::ExchangeFailed,
                AuthorizationStatus::Failed,
            ),
        ] {
            let request = awaiting(&mut core, &mut random);
            assert_eq!(
                core.receive_callback(request.attempt_id(), request.state(), BEFORE_DEADLINE),
                CallbackOutcome::ExchangeReady
            );
            assert!(core.exchange_failed(request.attempt_id(), failure));
            assert_eq!(core.status(), expected);
        }
    }

    #[test]
    fn secret_material_is_absent_from_debug_serialization_and_public_errors() {
        let mut core = core();
        let mut random = SequenceRandom::default();
        let request = awaiting(&mut core, &mut random);
        let state = request.state().to_owned();
        assert_eq!(
            core.receive_callback(request.attempt_id(), request.state(), BEFORE_DEADLINE),
            CallbackOutcome::ExchangeReady
        );
        let verifier = core
            .exchange_material(request.attempt_id())
            .expect("exchange")
            .pkce_verifier()
            .to_owned();

        let debug = format!(
            "{core:?} {request:?} {:?}",
            core.exchange_material(request.attempt_id())
        );
        assert!(!debug.contains(&state));
        assert!(!debug.contains(&verifier));
        let json = serde_json::to_string(&core.status()).expect("safe status serializes");
        assert!(!json.contains(&state));
        assert!(!json.contains(&verifier));

        let mut failure = AuthorizationCore::new(Duration::from_secs(30));
        let mut unavailable = SequenceRandom {
            fail: true,
            ..Default::default()
        };
        let error = failure
            .prepare(&mut unavailable)
            .expect_err("random failure");
        assert!(!error.to_string().contains(&state));
        assert_eq!(failure.status(), AuthorizationStatus::Failed);
    }
}
