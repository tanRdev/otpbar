//! Authoritative notification permission ownership over an injected OS port.

use std::fmt;

use crate::authorization::core::AuthorizationStatus;

/// Permission value observed from the operating system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NotificationPermission {
    /// Permission has not been requested or observed yet.
    #[default]
    Unknown,
    /// Notification delivery is allowed.
    Granted,
    /// Notification delivery is denied.
    Denied,
}

/// User-visible notification permission phase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NotificationPermissionStatus {
    /// No authoritative permission result is known.
    #[default]
    Unknown,
    /// The operating-system request is in progress.
    Requesting,
    /// Permission is granted and notifications are enabled.
    Granted,
    /// Permission is denied and notifications remain disabled.
    Denied,
    /// Permission cannot currently be queried or requested.
    Unavailable,
    /// The operating-system operation failed.
    Error,
}

/// Stable operating-system permission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsPermissionFailure {
    Unavailable,
    OperationFailed,
}

impl fmt::Display for OsPermissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "Notification permission is unavailable.",
            Self::OperationFailed => "The notification permission operation failed.",
        })
    }
}

impl std::error::Error for OsPermissionFailure {}

/// Boundary owning operating-system notification permission.
pub trait NotificationPermissionOs {
    fn request(&mut self) -> Result<NotificationPermission, OsPermissionFailure>;
    fn observe(&mut self) -> Result<NotificationPermission, OsPermissionFailure>;
}

/// Source of a permission request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionRequestTrigger {
    UserAction,
    Background,
}

/// Safe Desktop Session projection of notification permission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NotificationPermissionSnapshot {
    status: NotificationPermissionStatus,
    permission: NotificationPermission,
    enabled: bool,
    retryable: bool,
    system_settings_available: bool,
}

impl NotificationPermissionSnapshot {
    pub const fn status(self) -> NotificationPermissionStatus {
        self.status
    }

    pub const fn permission(self) -> NotificationPermission {
        self.permission
    }

    pub const fn enabled(self) -> bool {
        self.enabled
    }

    pub const fn retryable(self) -> bool {
        self.retryable
    }

    pub const fn system_settings_available(self) -> bool {
        self.system_settings_available
    }

    /// Notification permission never gates Gmail intake.
    pub const fn intake_available(self) -> bool {
        true
    }

    const fn requesting() -> Self {
        Self {
            status: NotificationPermissionStatus::Requesting,
            permission: NotificationPermission::Unknown,
            enabled: false,
            retryable: false,
            system_settings_available: false,
        }
    }

    const fn observed(permission: NotificationPermission) -> Self {
        match permission {
            NotificationPermission::Unknown => Self::default_snapshot(),
            NotificationPermission::Granted => Self {
                status: NotificationPermissionStatus::Granted,
                permission,
                enabled: true,
                retryable: false,
                system_settings_available: false,
            },
            NotificationPermission::Denied => Self {
                status: NotificationPermissionStatus::Denied,
                permission,
                enabled: false,
                retryable: false,
                system_settings_available: true,
            },
        }
    }

    const fn failed(failure: OsPermissionFailure) -> Self {
        Self {
            status: match failure {
                OsPermissionFailure::Unavailable => NotificationPermissionStatus::Unavailable,
                OsPermissionFailure::OperationFailed => NotificationPermissionStatus::Error,
            },
            permission: NotificationPermission::Unknown,
            enabled: false,
            retryable: true,
            system_settings_available: false,
        }
    }

    const fn default_snapshot() -> Self {
        Self {
            status: NotificationPermissionStatus::Unknown,
            permission: NotificationPermission::Unknown,
            enabled: false,
            retryable: false,
            system_settings_available: false,
        }
    }
}

/// Port adopting the permission projection into the Desktop Session.
pub trait NotificationPermissionSession {
    fn adopt(&mut self, snapshot: NotificationPermissionSnapshot);
}

/// Safe reason a permission operation did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationPermissionError {
    AuthorizationRequired,
    UserActionRequired,
    Os(OsPermissionFailure),
}

impl fmt::Display for NotificationPermissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthorizationRequired => {
                "Authorization is required before requesting notification permission."
            }
            Self::UserActionRequired => {
                "Notification permission can be requested only from a user action."
            }
            Self::Os(_) => "Notification permission could not be determined.",
        })
    }
}

impl std::error::Error for NotificationPermissionError {}

/// Permission operation result including the current safe projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPermissionOutcome {
    snapshot: NotificationPermissionSnapshot,
    error: Option<NotificationPermissionError>,
}

impl NotificationPermissionOutcome {
    pub const fn snapshot(self) -> NotificationPermissionSnapshot {
        self.snapshot
    }

    pub const fn error(self) -> Option<NotificationPermissionError> {
        self.error
    }
}

/// Notification permission state owner.
#[derive(Debug, Default)]
pub struct NotificationPermissionOwner {
    snapshot: NotificationPermissionSnapshot,
}

impl NotificationPermissionOwner {
    pub const fn snapshot(&self) -> NotificationPermissionSnapshot {
        self.snapshot
    }

    pub fn request<O, S>(
        &mut self,
        authorization: AuthorizationStatus,
        trigger: PermissionRequestTrigger,
        os: &mut O,
        session: &mut S,
    ) -> NotificationPermissionOutcome
    where
        O: NotificationPermissionOs,
        S: NotificationPermissionSession,
    {
        if authorization != AuthorizationStatus::Connected {
            return NotificationPermissionOutcome {
                snapshot: self.snapshot,
                error: Some(NotificationPermissionError::AuthorizationRequired),
            };
        } else if trigger != PermissionRequestTrigger::UserAction {
            return NotificationPermissionOutcome {
                snapshot: self.snapshot,
                error: Some(NotificationPermissionError::UserActionRequired),
            };
        }

        self.snapshot = NotificationPermissionSnapshot::requesting();
        session.adopt(self.snapshot);

        let permission = match os.request() {
            Ok(permission) => permission,
            Err(error) => {
                self.snapshot = NotificationPermissionSnapshot::failed(error);
                session.adopt(self.snapshot);
                return NotificationPermissionOutcome {
                    snapshot: self.snapshot,
                    error: Some(NotificationPermissionError::Os(error)),
                };
            }
        };
        self.snapshot = NotificationPermissionSnapshot::observed(permission);
        session.adopt(self.snapshot);

        NotificationPermissionOutcome {
            snapshot: self.snapshot,
            error: None,
        }
    }

    /// Reconciles launch or external permission drift without opening an OS prompt.
    pub fn reconcile<O, S>(&mut self, os: &mut O, session: &mut S) -> NotificationPermissionOutcome
    where
        O: NotificationPermissionOs,
        S: NotificationPermissionSession,
    {
        match os.observe() {
            Ok(permission) => {
                self.snapshot = NotificationPermissionSnapshot::observed(permission);
                session.adopt(self.snapshot);
                NotificationPermissionOutcome {
                    snapshot: self.snapshot,
                    error: None,
                }
            }
            Err(error) => {
                self.snapshot = NotificationPermissionSnapshot::failed(error);
                session.adopt(self.snapshot);
                NotificationPermissionOutcome {
                    snapshot: self.snapshot,
                    error: Some(NotificationPermissionError::Os(error)),
                }
            }
        }
    }
}
