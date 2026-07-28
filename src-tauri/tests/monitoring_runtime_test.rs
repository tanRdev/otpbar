use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use otpbar::{
    authorization::core::AuthorizationStatus,
    clock::SystemClock,
    intake::{
        runtime::spawn_monitoring,
        scheduler::{
            CheckCompleteness, CheckFuture, IntakeScheduler, IntakeTransport, JitterSource,
            MigrationReadiness, MonitoringHealthStatus,
        },
    },
};
use tokio::sync::{watch, Notify};

struct FakeTransport {
    checks: Arc<AtomicUsize>,
    checked: Arc<Notify>,
}

impl IntakeTransport for FakeTransport {
    fn check(&mut self) -> CheckFuture<'_> {
        self.checks.fetch_add(1, Ordering::AcqRel);
        self.checked.notify_waiters();
        Box::pin(async { Ok(CheckCompleteness::Complete) })
    }
}

struct NoJitter;

impl JitterSource for NoJitter {
    fn healthy_jitter_basis_points(&mut self) -> i32 {
        0
    }
}

#[tokio::test]
async fn monitoring_waits_for_migration_and_authorization_then_stops_on_disconnect() {
    let checks = Arc::new(AtomicUsize::new(0));
    let checked = Arc::new(Notify::new());
    let (authorization, statuses) = watch::channel(AuthorizationStatus::Connected);
    let scheduler = IntakeScheduler::new(
        FakeTransport {
            checks: checks.clone(),
            checked: checked.clone(),
        },
        Arc::new(SystemClock),
        NoJitter,
    );
    let monitoring = spawn_monitoring(scheduler, statuses);

    tokio::task::yield_now().await;
    assert_eq!(checks.load(Ordering::Acquire), 0);
    assert_eq!(
        monitoring.health().status(),
        MonitoringHealthStatus::Stopped
    );

    monitoring
        .set_migration_readiness(MigrationReadiness::Ready)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while checks.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ready connected monitoring checks immediately");
    assert_eq!(checks.load(Ordering::Acquire), 1);

    authorization
        .send(AuthorizationStatus::Disconnected)
        .unwrap();
    let mut health = monitoring.subscribe();
    tokio::time::timeout(Duration::from_secs(1), async {
        while health.borrow_and_update().status() != MonitoringHealthStatus::Stopped {
            health.changed().await.unwrap();
        }
    })
    .await
    .expect("disconnect stops monitoring within one second");
}

#[tokio::test]
async fn refresh_required_is_a_distinct_safe_monitoring_health() {
    let (authorization, statuses) = watch::channel(AuthorizationStatus::Connected);
    let scheduler = IntakeScheduler::new(
        FakeTransport {
            checks: Arc::new(AtomicUsize::new(0)),
            checked: Arc::new(Notify::new()),
        },
        Arc::new(SystemClock),
        NoJitter,
    );
    let monitoring = spawn_monitoring(scheduler, statuses);
    monitoring
        .set_migration_readiness(MigrationReadiness::Ready)
        .await
        .unwrap();

    authorization
        .send(AuthorizationStatus::RefreshRequired)
        .unwrap();
    let mut health = monitoring.subscribe();
    tokio::time::timeout(Duration::from_secs(1), async {
        while health.borrow_and_update().status() != MonitoringHealthStatus::AuthorizationRequired {
            health.changed().await.unwrap();
        }
    })
    .await
    .expect("refresh requirement is published promptly");
}
