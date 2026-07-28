//! Authoritative Start at Login reconciliation over injected desktop ports.

use std::fmt;

/// Stable failures returned by the macOS registration adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationFailure {
    /// Registration APIs are unavailable in the current environment.
    Unavailable,
    /// macOS denied the requested operation.
    PermissionDenied,
    /// The registration operation failed without a more specific safe category.
    OperationFailed,
}

impl fmt::Display for RegistrationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "Start at Login is unavailable.",
            Self::PermissionDenied => "macOS denied Start at Login access.",
            Self::OperationFailed => "The Start at Login operation failed.",
        })
    }
}

impl std::error::Error for RegistrationFailure {}

/// Stable failures returned while persisting the observed macOS value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceFailure {
    /// Durable Settings are temporarily unavailable.
    Unavailable,
    /// Settings changed concurrently and require reconciliation.
    Conflict,
}

impl fmt::Display for PersistenceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "Observed Start at Login could not be saved.",
            Self::Conflict => "Settings changed while Start at Login was being reconciled.",
        })
    }
}

impl std::error::Error for PersistenceFailure {}

/// Port owning macOS Start at Login mutation and authoritative observation.
pub trait StartAtLoginRegistration {
    /// Requests a registration change.
    fn request(&mut self, enabled: bool) -> Result<(), RegistrationFailure>;

    /// Reads the authoritative macOS registration value.
    fn observe(&mut self) -> Result<bool, RegistrationFailure>;
}

/// Port persisting only a value already observed from macOS.
pub trait ObservedStartAtLoginPersistence {
    /// Persists the authoritative observed value.
    fn persist_observed(&mut self, enabled: bool) -> Result<(), PersistenceFailure>;
}

/// Port adopting Start at Login into the Desktop Session.
pub trait StartAtLoginSession {
    /// Adopts one safe full Start at Login projection.
    fn adopt(&mut self, snapshot: StartAtLoginSnapshot);
}

/// User-visible Start at Login state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartAtLoginStatus {
    /// macOS registration is observed disabled.
    Off,
    /// An enable request is in progress.
    Enabling,
    /// macOS registration is observed enabled.
    On,
    /// A disable request is in progress.
    Disabling,
    /// Registration could not be read back.
    ReadBackFailed,
    /// macOS was observed, but its value could not be persisted.
    PersistenceDegraded,
    /// The requested macOS operation failed.
    Unavailable,
}

/// Safe Desktop Session projection of Start at Login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartAtLoginSnapshot {
    status: StartAtLoginStatus,
    observed: Option<bool>,
    retryable: bool,
}

impl StartAtLoginSnapshot {
    /// Returns the user-visible phase.
    pub const fn status(self) -> StartAtLoginStatus {
        self.status
    }

    /// Returns the last authoritative macOS value, or `None` when unknown.
    pub const fn observed(self) -> Option<bool> {
        self.observed
    }

    /// Reports whether reconciliation may be retried.
    pub const fn retryable(self) -> bool {
        self.retryable
    }

    const fn from_observed(value: bool) -> Self {
        Self {
            status: if value {
                StartAtLoginStatus::On
            } else {
                StartAtLoginStatus::Off
            },
            observed: Some(value),
            retryable: false,
        }
    }

    const fn transition(
        status: StartAtLoginStatus,
        observed: Option<bool>,
        retryable: bool,
    ) -> Self {
        Self {
            status,
            observed,
            retryable,
        }
    }
}

/// Safe, typed reason that reconciliation is degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartAtLoginError {
    /// The requested macOS mutation failed.
    Request(RegistrationFailure),
    /// Authoritative read-back failed.
    ReadBack(RegistrationFailure),
    /// Persisting an observed macOS value failed.
    Persistence(PersistenceFailure),
}

impl fmt::Display for StartAtLoginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Request(_) => "The Start at Login request failed.",
            Self::ReadBack(_) => "Start at Login read-back failed.",
            Self::Persistence(_) => {
                "The observed Start at Login value is active, but Settings reconciliation failed."
            }
        })
    }
}

impl std::error::Error for StartAtLoginError {}

/// Result carrying the authoritative projection even when reconciliation degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartAtLoginOutcome {
    snapshot: StartAtLoginSnapshot,
    error: Option<StartAtLoginError>,
}

impl StartAtLoginOutcome {
    /// Returns the Desktop Session projection produced by the operation.
    pub const fn snapshot(self) -> StartAtLoginSnapshot {
        self.snapshot
    }

    /// Returns a safe typed degradation, if one occurred.
    pub const fn error(self) -> Option<StartAtLoginError> {
        self.error
    }
}

/// Start at Login reconciliation core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartAtLogin {
    snapshot: StartAtLoginSnapshot,
}

impl Default for StartAtLogin {
    fn default() -> Self {
        Self {
            snapshot: StartAtLoginSnapshot::from_observed(false),
        }
    }
}

impl StartAtLogin {
    /// Restores the stale persisted hint that launch reconciliation must replace.
    pub const fn from_persisted(enabled: bool) -> Self {
        Self {
            snapshot: StartAtLoginSnapshot::from_observed(enabled),
        }
    }

    /// Returns the current Desktop Session projection.
    pub const fn snapshot(&self) -> StartAtLoginSnapshot {
        self.snapshot
    }

    /// Requests a macOS mutation, then reconciles from authoritative read-back.
    pub fn request<R, P, S>(
        &mut self,
        enabled: bool,
        registration: &mut R,
        persistence: &mut P,
        session: &mut S,
    ) -> StartAtLoginOutcome
    where
        R: StartAtLoginRegistration,
        P: ObservedStartAtLoginPersistence,
        S: StartAtLoginSession,
    {
        self.snapshot = StartAtLoginSnapshot::transition(
            if enabled {
                StartAtLoginStatus::Enabling
            } else {
                StartAtLoginStatus::Disabling
            },
            self.snapshot.observed,
            false,
        );
        session.adopt(self.snapshot);

        if let Err(error) = registration.request(enabled) {
            self.snapshot =
                StartAtLoginSnapshot::transition(StartAtLoginStatus::Unavailable, None, true);
            session.adopt(self.snapshot);
            return StartAtLoginOutcome {
                snapshot: self.snapshot,
                error: Some(StartAtLoginError::Request(error)),
            };
        }

        self.reconcile(registration, persistence, session)
    }

    /// Reconciles launch, drift, or a degraded retry from authoritative macOS state.
    pub fn reconcile<R, P, S>(
        &mut self,
        registration: &mut R,
        persistence: &mut P,
        session: &mut S,
    ) -> StartAtLoginOutcome
    where
        R: StartAtLoginRegistration,
        P: ObservedStartAtLoginPersistence,
        S: StartAtLoginSession,
    {
        let observed = match registration.observe() {
            Ok(observed) => observed,
            Err(error) => {
                self.snapshot = StartAtLoginSnapshot::transition(
                    StartAtLoginStatus::ReadBackFailed,
                    None,
                    true,
                );
                session.adopt(self.snapshot);
                return StartAtLoginOutcome {
                    snapshot: self.snapshot,
                    error: Some(StartAtLoginError::ReadBack(error)),
                };
            }
        };

        self.snapshot = StartAtLoginSnapshot::from_observed(observed);
        session.adopt(self.snapshot);

        if let Err(error) = persistence.persist_observed(observed) {
            self.snapshot = StartAtLoginSnapshot::transition(
                StartAtLoginStatus::PersistenceDegraded,
                Some(observed),
                true,
            );
            session.adopt(self.snapshot);
            return StartAtLoginOutcome {
                snapshot: self.snapshot,
                error: Some(StartAtLoginError::Persistence(error)),
            };
        }

        StartAtLoginOutcome {
            snapshot: self.snapshot,
            error: None,
        }
    }
}
