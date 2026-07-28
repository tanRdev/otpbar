use otpbar::desktop::start_at_login::{
    ObservedStartAtLoginPersistence, PersistenceFailure, RegistrationFailure, StartAtLogin,
    StartAtLoginError, StartAtLoginRegistration, StartAtLoginSession, StartAtLoginSnapshot,
    StartAtLoginStatus,
};

#[derive(Default)]
struct Session {
    snapshots: Vec<StartAtLoginSnapshot>,
}

impl StartAtLoginSession for Session {
    fn adopt(&mut self, snapshot: StartAtLoginSnapshot) {
        self.snapshots.push(snapshot);
    }
}

struct FailedRegistration;

impl StartAtLoginRegistration for FailedRegistration {
    fn request(&mut self, _enabled: bool) -> Result<(), RegistrationFailure> {
        Err(RegistrationFailure::Unavailable)
    }

    fn observe(&mut self) -> Result<bool, RegistrationFailure> {
        panic!("failed mutation must not claim a read-back")
    }
}

struct UnexpectedPersistence;

impl ObservedStartAtLoginPersistence for UnexpectedPersistence {
    fn persist_observed(&mut self, _enabled: bool) -> Result<(), PersistenceFailure> {
        panic!("failed mutation must not persist")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Request(bool),
    Observe,
    Session(StartAtLoginStatus, Option<bool>),
    Persist(bool),
}

struct LoggedRegistration {
    observed: Result<bool, RegistrationFailure>,
    events: Rc<RefCell<Vec<Event>>>,
}

impl StartAtLoginRegistration for LoggedRegistration {
    fn request(&mut self, enabled: bool) -> Result<(), RegistrationFailure> {
        self.events.borrow_mut().push(Event::Request(enabled));
        Ok(())
    }

    fn observe(&mut self) -> Result<bool, RegistrationFailure> {
        self.events.borrow_mut().push(Event::Observe);
        self.observed
    }
}

struct LoggedPersistence {
    result: Result<(), PersistenceFailure>,
    events: Rc<RefCell<Vec<Event>>>,
}

impl ObservedStartAtLoginPersistence for LoggedPersistence {
    fn persist_observed(&mut self, enabled: bool) -> Result<(), PersistenceFailure> {
        self.events.borrow_mut().push(Event::Persist(enabled));
        self.result
    }
}

struct LoggedSession {
    events: Rc<RefCell<Vec<Event>>>,
}

impl StartAtLoginSession for LoggedSession {
    fn adopt(&mut self, snapshot: StartAtLoginSnapshot) {
        self.events
            .borrow_mut()
            .push(Event::Session(snapshot.status(), snapshot.observed()));
    }
}

#[test]
fn start_at_login_defaults_off() {
    let integration = StartAtLogin::default();

    assert_eq!(integration.snapshot().status(), StartAtLoginStatus::Off);
    assert_eq!(integration.snapshot().observed(), Some(false));
    assert!(!integration.snapshot().retryable());
}

#[test]
fn failed_request_reports_retryable_unknown_without_false_rollback() {
    let mut integration = StartAtLogin::default();
    let mut registration = FailedRegistration;
    let mut persistence = UnexpectedPersistence;
    let mut session = Session::default();

    let outcome = integration.request(true, &mut registration, &mut persistence, &mut session);

    assert_eq!(
        outcome.error(),
        Some(StartAtLoginError::Request(RegistrationFailure::Unavailable))
    );
    assert_eq!(outcome.snapshot().status(), StartAtLoginStatus::Unavailable);
    assert_eq!(outcome.snapshot().observed(), None);
    assert!(outcome.snapshot().retryable());
    assert_eq!(
        session
            .snapshots
            .iter()
            .map(|snapshot| snapshot.status())
            .collect::<Vec<_>>(),
        vec![
            StartAtLoginStatus::Enabling,
            StartAtLoginStatus::Unavailable
        ]
    );
}

#[test]
fn successful_request_adopts_authoritative_new_value_before_persistence() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut integration = StartAtLogin::default();
    let mut registration = LoggedRegistration {
        observed: Ok(true),
        events: events.clone(),
    };
    let mut persistence = LoggedPersistence {
        result: Ok(()),
        events: events.clone(),
    };
    let mut session = LoggedSession {
        events: events.clone(),
    };

    let outcome = integration.request(true, &mut registration, &mut persistence, &mut session);

    assert_eq!(outcome.error(), None);
    assert_eq!(outcome.snapshot().status(), StartAtLoginStatus::On);
    assert_eq!(outcome.snapshot().observed(), Some(true));
    assert_eq!(
        events.borrow().as_slice(),
        [
            Event::Session(StartAtLoginStatus::Enabling, Some(false)),
            Event::Request(true),
            Event::Observe,
            Event::Session(StartAtLoginStatus::On, Some(true)),
            Event::Persist(true),
        ]
    );
}

#[test]
fn read_back_old_is_authoritative_and_read_failure_stays_unknown() {
    let old_events = Rc::new(RefCell::new(Vec::new()));
    let mut integration = StartAtLogin::default();
    let mut old_registration = LoggedRegistration {
        observed: Ok(false),
        events: old_events.clone(),
    };
    let mut old_persistence = LoggedPersistence {
        result: Ok(()),
        events: old_events.clone(),
    };
    let mut old_session = LoggedSession {
        events: old_events.clone(),
    };

    let old = integration.request(
        true,
        &mut old_registration,
        &mut old_persistence,
        &mut old_session,
    );

    assert_eq!(old.error(), None);
    assert_eq!(old.snapshot().status(), StartAtLoginStatus::Off);
    assert_eq!(old.snapshot().observed(), Some(false));
    assert_eq!(old_events.borrow().last(), Some(&Event::Persist(false)));

    let failed_events = Rc::new(RefCell::new(Vec::new()));
    let mut failed_registration = LoggedRegistration {
        observed: Err(RegistrationFailure::OperationFailed),
        events: failed_events.clone(),
    };
    let mut failed_persistence = LoggedPersistence {
        result: Ok(()),
        events: failed_events.clone(),
    };
    let mut failed_session = LoggedSession {
        events: failed_events.clone(),
    };

    let failed = integration.request(
        true,
        &mut failed_registration,
        &mut failed_persistence,
        &mut failed_session,
    );

    assert_eq!(
        failed.error(),
        Some(StartAtLoginError::ReadBack(
            RegistrationFailure::OperationFailed
        ))
    );
    assert_eq!(
        failed.snapshot().status(),
        StartAtLoginStatus::ReadBackFailed
    );
    assert_eq!(failed.snapshot().observed(), None);
    assert!(failed.snapshot().retryable());
    assert!(!failed_events
        .borrow()
        .iter()
        .any(|event| matches!(event, Event::Persist(_))));
}

#[test]
fn persistence_failure_keeps_observed_os_value_and_retry_reconciles_without_mutation() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut integration = StartAtLogin::default();
    let mut registration = LoggedRegistration {
        observed: Ok(true),
        events: events.clone(),
    };
    let mut failed_persistence = LoggedPersistence {
        result: Err(PersistenceFailure::Conflict),
        events: events.clone(),
    };
    let mut session = LoggedSession {
        events: events.clone(),
    };

    let degraded = integration.request(
        true,
        &mut registration,
        &mut failed_persistence,
        &mut session,
    );

    assert_eq!(
        degraded.error(),
        Some(StartAtLoginError::Persistence(PersistenceFailure::Conflict))
    );
    assert_eq!(
        degraded.snapshot().status(),
        StartAtLoginStatus::PersistenceDegraded
    );
    assert_eq!(degraded.snapshot().observed(), Some(true));
    assert!(degraded.snapshot().retryable());
    assert_eq!(
        events.borrow().as_slice(),
        [
            Event::Session(StartAtLoginStatus::Enabling, Some(false)),
            Event::Request(true),
            Event::Observe,
            Event::Session(StartAtLoginStatus::On, Some(true)),
            Event::Persist(true),
            Event::Session(StartAtLoginStatus::PersistenceDegraded, Some(true)),
        ]
    );

    events.borrow_mut().clear();
    let mut recovered_persistence = LoggedPersistence {
        result: Ok(()),
        events: events.clone(),
    };
    let recovered =
        integration.reconcile(&mut registration, &mut recovered_persistence, &mut session);

    assert_eq!(recovered.error(), None);
    assert_eq!(recovered.snapshot().status(), StartAtLoginStatus::On);
    assert_eq!(
        events.borrow().as_slice(),
        [
            Event::Observe,
            Event::Session(StartAtLoginStatus::On, Some(true)),
            Event::Persist(true),
        ]
    );
}

#[test]
fn launch_adopts_external_drift_in_both_directions_without_mutating_macos() {
    for (persisted, os_observed, expected_status) in [
        (false, true, StartAtLoginStatus::On),
        (true, false, StartAtLoginStatus::Off),
    ] {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut integration = StartAtLogin::from_persisted(persisted);
        let mut registration = LoggedRegistration {
            observed: Ok(os_observed),
            events: events.clone(),
        };
        let mut persistence = LoggedPersistence {
            result: Ok(()),
            events: events.clone(),
        };
        let mut session = LoggedSession {
            events: events.clone(),
        };

        let outcome = integration.reconcile(&mut registration, &mut persistence, &mut session);

        assert_eq!(outcome.error(), None);
        assert_eq!(outcome.snapshot().status(), expected_status);
        assert_eq!(outcome.snapshot().observed(), Some(os_observed));
        assert_eq!(
            events.borrow().as_slice(),
            [
                Event::Observe,
                Event::Session(expected_status, Some(os_observed)),
                Event::Persist(os_observed),
            ]
        );
    }
}

#[test]
fn restart_after_each_crash_boundary_reobserves_macos_and_repairs_persistence() {
    let crash_states = [
        ("before mutation", false, false),
        ("after mutation", true, false),
        ("after read-back", true, false),
        ("after persistence", true, true),
    ];

    for (boundary, os_observed, persisted) in crash_states {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut restarted = StartAtLogin::from_persisted(persisted);
        let mut registration = LoggedRegistration {
            observed: Ok(os_observed),
            events: events.clone(),
        };
        let mut persistence = LoggedPersistence {
            result: Ok(()),
            events: events.clone(),
        };
        let mut session = LoggedSession {
            events: events.clone(),
        };

        let outcome = restarted.reconcile(&mut registration, &mut persistence, &mut session);

        assert_eq!(
            outcome.snapshot().observed(),
            Some(os_observed),
            "{boundary}"
        );
        assert_eq!(events.borrow().first(), Some(&Event::Observe), "{boundary}");
        assert_eq!(
            events.borrow().last(),
            Some(&Event::Persist(os_observed)),
            "{boundary}"
        );
        assert!(
            !events
                .borrow()
                .iter()
                .any(|event| matches!(event, Event::Request(_))),
            "{boundary}"
        );
    }
}

#[test]
fn failures_are_typed_and_have_only_fixed_safe_output() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<RegistrationFailure>();
    assert_error::<PersistenceFailure>();
    assert_error::<StartAtLoginError>();

    let failures = [
        StartAtLoginError::Request(RegistrationFailure::PermissionDenied),
        StartAtLoginError::ReadBack(RegistrationFailure::OperationFailed),
        StartAtLoginError::Persistence(PersistenceFailure::Unavailable),
    ];
    for failure in failures {
        let display = failure.to_string();
        let debug = format!("{failure:?}");
        assert!(!display.is_empty());
        assert!(!debug.is_empty());
        assert!(!display.contains("secret"));
        assert!(!debug.contains("secret"));
    }
}
use std::cell::RefCell;
use std::rc::Rc;
