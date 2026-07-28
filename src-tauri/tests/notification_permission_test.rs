use otpbar::authorization::core::AuthorizationStatus;
use otpbar::notifications::permission::{
    NotificationPermission, NotificationPermissionError, NotificationPermissionOs,
    NotificationPermissionOwner, NotificationPermissionSession, NotificationPermissionSnapshot,
    NotificationPermissionStatus, OsPermissionFailure, PermissionRequestTrigger,
};

struct UnexpectedOs;

impl NotificationPermissionOs for UnexpectedOs {
    fn request(
        &mut self,
    ) -> Result<NotificationPermission, otpbar::notifications::permission::OsPermissionFailure>
    {
        panic!("rejected request must not reach the operating system")
    }

    fn observe(
        &mut self,
    ) -> Result<NotificationPermission, otpbar::notifications::permission::OsPermissionFailure>
    {
        panic!("rejected request must not query the operating system")
    }
}

#[derive(Default)]
struct Session {
    snapshots: Vec<NotificationPermissionSnapshot>,
}

impl NotificationPermissionSession for Session {
    fn adopt(&mut self, snapshot: NotificationPermissionSnapshot) {
        self.snapshots.push(snapshot);
    }
}

struct OsResult(
    Result<NotificationPermission, otpbar::notifications::permission::OsPermissionFailure>,
);

impl NotificationPermissionOs for OsResult {
    fn request(
        &mut self,
    ) -> Result<NotificationPermission, otpbar::notifications::permission::OsPermissionFailure>
    {
        self.0
    }

    fn observe(
        &mut self,
    ) -> Result<NotificationPermission, otpbar::notifications::permission::OsPermissionFailure>
    {
        self.0
    }
}

struct ObserveOnly(Result<NotificationPermission, OsPermissionFailure>);

impl NotificationPermissionOs for ObserveOnly {
    fn request(&mut self) -> Result<NotificationPermission, OsPermissionFailure> {
        panic!("reconciliation must never request permission")
    }

    fn observe(&mut self) -> Result<NotificationPermission, OsPermissionFailure> {
        self.0
    }
}

#[test]
fn notifications_default_to_unknown_and_disabled() {
    let owner = NotificationPermissionOwner::default();

    assert_eq!(
        owner.snapshot().status(),
        NotificationPermissionStatus::Unknown
    );
    assert_eq!(
        owner.snapshot().permission(),
        NotificationPermission::Unknown
    );
    assert!(!owner.snapshot().enabled());
    assert!(!owner.snapshot().retryable());
    assert!(!owner.snapshot().system_settings_available());
}

#[test]
fn permission_request_requires_authorization_and_an_explicit_user_action() {
    let cases = [
        (
            AuthorizationStatus::Disconnected,
            PermissionRequestTrigger::UserAction,
            NotificationPermissionError::AuthorizationRequired,
        ),
        (
            AuthorizationStatus::Connected,
            PermissionRequestTrigger::Background,
            NotificationPermissionError::UserActionRequired,
        ),
    ];

    for (authorization, trigger, expected) in cases {
        let mut owner = NotificationPermissionOwner::default();
        let mut os = UnexpectedOs;
        let mut session = Session::default();

        let outcome = owner.request(authorization, trigger, &mut os, &mut session);

        assert_eq!(outcome.error(), Some(expected));
        assert_eq!(outcome.snapshot(), owner.snapshot());
        assert_eq!(
            outcome.snapshot().status(),
            NotificationPermissionStatus::Unknown
        );
        assert!(!outcome.snapshot().enabled());
        assert!(session.snapshots.is_empty());
    }
}

#[test]
fn explicit_authorized_request_publishes_requesting_then_enables_only_on_grant() {
    let mut owner = NotificationPermissionOwner::default();
    let mut os = OsResult(Ok(NotificationPermission::Granted));
    let mut session = Session::default();

    let outcome = owner.request(
        AuthorizationStatus::Connected,
        PermissionRequestTrigger::UserAction,
        &mut os,
        &mut session,
    );

    assert_eq!(outcome.error(), None);
    assert_eq!(
        outcome.snapshot().status(),
        NotificationPermissionStatus::Granted
    );
    assert_eq!(
        outcome.snapshot().permission(),
        NotificationPermission::Granted
    );
    assert!(outcome.snapshot().enabled());
    assert_eq!(
        session
            .snapshots
            .iter()
            .map(|snapshot| snapshot.status())
            .collect::<Vec<_>>(),
        vec![
            NotificationPermissionStatus::Requesting,
            NotificationPermissionStatus::Granted,
        ]
    );
}

#[test]
fn denial_stays_disabled_and_exposes_system_settings_without_blocking_intake() {
    let mut owner = NotificationPermissionOwner::default();
    let mut os = OsResult(Ok(NotificationPermission::Denied));
    let mut session = Session::default();

    let outcome = owner.request(
        AuthorizationStatus::Connected,
        PermissionRequestTrigger::UserAction,
        &mut os,
        &mut session,
    );

    assert_eq!(outcome.error(), None);
    assert_eq!(
        outcome.snapshot().status(),
        NotificationPermissionStatus::Denied
    );
    assert_eq!(
        outcome.snapshot().permission(),
        NotificationPermission::Denied
    );
    assert!(!outcome.snapshot().enabled());
    assert!(outcome.snapshot().system_settings_available());
    assert!(outcome.snapshot().intake_available());
}

#[test]
fn os_unavailable_and_error_are_disabled_retryable_states() {
    for (failure, expected_status) in [
        (
            OsPermissionFailure::Unavailable,
            NotificationPermissionStatus::Unavailable,
        ),
        (
            OsPermissionFailure::OperationFailed,
            NotificationPermissionStatus::Error,
        ),
    ] {
        let mut owner = NotificationPermissionOwner::default();
        let mut failed_os = OsResult(Err(failure));
        let mut session = Session::default();

        let failed = owner.request(
            AuthorizationStatus::Connected,
            PermissionRequestTrigger::UserAction,
            &mut failed_os,
            &mut session,
        );

        assert_eq!(
            failed.error(),
            Some(NotificationPermissionError::Os(failure))
        );
        assert_eq!(failed.snapshot().status(), expected_status);
        assert!(!failed.snapshot().enabled());
        assert!(failed.snapshot().retryable());
        assert!(failed.snapshot().intake_available());

        let mut recovered_os = OsResult(Ok(NotificationPermission::Granted));
        let recovered = owner.request(
            AuthorizationStatus::Connected,
            PermissionRequestTrigger::UserAction,
            &mut recovered_os,
            &mut session,
        );

        assert_eq!(recovered.error(), None);
        assert_eq!(
            recovered.snapshot().status(),
            NotificationPermissionStatus::Granted
        );
        assert!(recovered.snapshot().enabled());
    }
}

#[test]
fn reconciliation_adopts_external_revocation_and_disables_notifications() {
    let mut owner = NotificationPermissionOwner::default();
    let mut granting_os = OsResult(Ok(NotificationPermission::Granted));
    let mut session = Session::default();
    let granted = owner.request(
        AuthorizationStatus::Connected,
        PermissionRequestTrigger::UserAction,
        &mut granting_os,
        &mut session,
    );
    assert!(granted.snapshot().enabled());

    let mut revoked_os = ObserveOnly(Ok(NotificationPermission::Denied));
    let revoked = owner.reconcile(&mut revoked_os, &mut session);

    assert_eq!(revoked.error(), None);
    assert_eq!(
        revoked.snapshot().permission(),
        NotificationPermission::Denied
    );
    assert_eq!(
        revoked.snapshot().status(),
        NotificationPermissionStatus::Denied
    );
    assert!(!revoked.snapshot().enabled());
    assert!(revoked.snapshot().system_settings_available());
    assert!(revoked.snapshot().intake_available());
}

#[test]
fn permission_failures_are_typed_and_have_only_fixed_safe_output() {
    fn assert_error(error: &dyn std::error::Error) {
        assert!(!error.to_string().is_empty());
    }

    for failure in [
        OsPermissionFailure::Unavailable,
        OsPermissionFailure::OperationFailed,
    ] {
        assert_error(&failure);
        assert!(!failure.to_string().contains("token"));
    }

    for error in [
        NotificationPermissionError::AuthorizationRequired,
        NotificationPermissionError::UserActionRequired,
        NotificationPermissionError::Os(OsPermissionFailure::OperationFailed),
    ] {
        assert_error(&error);
        assert!(!error.to_string().contains("token"));
    }
}
