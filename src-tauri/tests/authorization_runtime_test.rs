use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use otpbar::{
    authorization::{
        core::{AuthorizationRequest, AuthorizationStatus, ExchangeMaterial},
        credentials::{CredentialBundle, CredentialRepository},
        runtime::{
            spawn_authorization, AuthorizationBrowser, AuthorizationTransport,
            AuthorizationTransportError,
        },
    },
    clock::Timestamp,
    domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
    ports::{RandomSource, SecretStore},
};

#[derive(Clone, Default)]
struct FakeSecrets {
    values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    fail_deletes: Arc<std::sync::atomic::AtomicBool>,
}

impl SecretStore for FakeSecrets {
    fn read_secret(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
        Ok(self
            .values
            .lock()
            .expect("fake secrets lock")
            .get(key)
            .cloned())
    }

    fn write_secret(&mut self, key: &str, value: &[u8]) -> Result<(), ErrorEnvelope> {
        self.values
            .lock()
            .expect("fake secrets lock")
            .insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete_secret(&mut self, key: &str) -> Result<(), ErrorEnvelope> {
        if self.fail_deletes.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ErrorEnvelope::new(
                ErrorCode::StorageUnavailable,
                UserMessage::LocalDataUnavailable,
                true,
            ));
        }
        self.values.lock().expect("fake secrets lock").remove(key);
        Ok(())
    }
}

struct UnexpectedTransport;

impl AuthorizationTransport for UnexpectedTransport {
    fn authorization_url(
        &self,
        _request: &AuthorizationRequest,
        _redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError> {
        panic!("startup restore must not reach the provider")
    }

    fn exchange<'a>(
        &'a self,
        _authorization_code: &'a str,
        _material: ExchangeMaterial<'a>,
        _redirect_uri: &'a str,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        panic!("startup restore must not exchange")
    }
}

struct UnexpectedBrowser;

impl AuthorizationBrowser for UnexpectedBrowser {
    fn open(&self, _url: &str) -> Result<(), AuthorizationTransportError> {
        panic!("startup restore must not open a browser")
    }
}

struct SuccessfulTransport;

impl AuthorizationTransport for SuccessfulTransport {
    fn authorization_url(
        &self,
        request: &AuthorizationRequest,
        redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError> {
        let mut url = reqwest::Url::parse("https://fake.provider/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", request.state());
        Ok(url.into())
    }

    fn exchange<'a>(
        &'a self,
        _authorization_code: &'a str,
        _material: ExchangeMaterial<'a>,
        _redirect_uri: &'a str,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(async {
            CredentialBundle::new(
                "fake-access".to_owned(),
                "fake-refresh".to_owned(),
                Timestamp::from_unix_millis(i64::MAX),
                "person@example.com".to_owned(),
            )
            .map_err(|_| AuthorizationTransportError::Unavailable)
        })
    }
}

struct RefreshingTransport {
    result: Result<(), AuthorizationTransportError>,
}

impl AuthorizationTransport for RefreshingTransport {
    fn authorization_url(
        &self,
        _request: &AuthorizationRequest,
        _redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError> {
        panic!("startup refresh must not start browser authorization")
    }

    fn exchange<'a>(
        &'a self,
        _authorization_code: &'a str,
        _material: ExchangeMaterial<'a>,
        _redirect_uri: &'a str,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        panic!("startup refresh must not exchange an authorization code")
    }

    fn refresh<'a>(
        &'a self,
        existing: &'a CredentialBundle,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.result?;
            CredentialBundle::new(
                "refreshed-access".to_owned(),
                existing.refresh_token().to_owned(),
                Timestamp::from_unix_millis(i64::MAX),
                existing.mailbox_identity().to_owned(),
            )
            .map_err(|_| AuthorizationTransportError::Unavailable)
        })
    }
}

struct PendingTransport;

impl AuthorizationTransport for PendingTransport {
    fn authorization_url(
        &self,
        request: &AuthorizationRequest,
        redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError> {
        SuccessfulTransport.authorization_url(request, redirect_uri)
    }

    fn exchange<'a>(
        &'a self,
        _authorization_code: &'a str,
        _material: ExchangeMaterial<'a>,
        _redirect_uri: &'a str,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(std::future::pending())
    }
}

struct PendingRefreshTransport;

impl AuthorizationTransport for PendingRefreshTransport {
    fn authorization_url(
        &self,
        _request: &AuthorizationRequest,
        _redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError> {
        panic!("startup refresh must not start browser authorization")
    }

    fn exchange<'a>(
        &'a self,
        _authorization_code: &'a str,
        _material: ExchangeMaterial<'a>,
        _redirect_uri: &'a str,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        panic!("startup refresh must not exchange an authorization code")
    }

    fn refresh<'a>(
        &'a self,
        _existing: &'a CredentialBundle,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(std::future::pending())
    }
}

struct CallbackBrowser;

impl AuthorizationBrowser for CallbackBrowser {
    fn open(&self, url: &str) -> Result<(), AuthorizationTransportError> {
        let url = reqwest::Url::parse(url).map_err(|_| AuthorizationTransportError::Unavailable)?;
        let query = url.query_pairs().collect::<BTreeMap<_, _>>();
        let redirect = query
            .get("redirect_uri")
            .expect("fake provider redirect")
            .to_string();
        let state = query.get("state").expect("fake provider state").to_string();
        tokio::spawn(async move {
            let mut callback = reqwest::Url::parse(&redirect).expect("loopback redirect");
            callback
                .query_pairs_mut()
                .append_pair("code", "fake-code")
                .append_pair("state", &state);
            let _ = reqwest::get(callback).await;
        });
        Ok(())
    }
}

#[derive(Default)]
struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), ErrorEnvelope> {
        output.fill(7);
        Ok(())
    }
}

#[tokio::test]
async fn startup_restores_before_accepting_authorization_work() {
    let repository = CredentialRepository::new(FakeSecrets::default());
    let handle = spawn_authorization(
        repository,
        Arc::new(UnexpectedTransport),
        Arc::new(UnexpectedBrowser),
        FixedRandom,
    );

    assert_eq!(
        handle.wait_until_restored().await,
        AuthorizationStatus::Disconnected
    );
    assert_eq!(handle.status(), AuthorizationStatus::Disconnected);
}

#[tokio::test]
async fn expired_startup_credentials_refresh_and_persist_before_connected_or_use() {
    let secrets = FakeSecrets::default();
    let expired = CredentialBundle::new(
        "expired-access".to_owned(),
        "refresh-secret".to_owned(),
        Timestamp::from_unix_millis(0),
        "private@example.com".to_owned(),
    )
    .unwrap();
    CredentialRepository::new(secrets.clone())
        .persist(&expired)
        .unwrap();
    let handle = spawn_authorization(
        CredentialRepository::new(secrets.clone()),
        Arc::new(RefreshingTransport { result: Ok(()) }),
        Arc::new(UnexpectedBrowser),
        FixedRandom,
    );

    assert_eq!(
        handle.wait_until_restored().await,
        AuthorizationStatus::Connected
    );
    let persisted = CredentialRepository::new(secrets)
        .restore()
        .unwrap()
        .expect("refreshed credentials persisted before connected");
    assert_eq!(persisted.access_token(), "refreshed-access");

    let credential = handle
        .authorized_credential()
        .await
        .expect("connected runtime provides a safe request credential");
    assert_eq!(credential.access_token(), "refreshed-access");
    assert_eq!(credential.mailbox_identity(), "private@example.com");
    let debug = format!("{credential:?}");
    assert!(!debug.contains("refreshed-access"));
    assert!(!debug.contains("refresh-secret"));
    assert!(!debug.contains("private@example.com"));
}

#[tokio::test]
async fn invalid_startup_refresh_requires_reauthorization_and_never_connects() {
    let secrets = FakeSecrets::default();
    CredentialRepository::new(secrets.clone())
        .persist(
            &CredentialBundle::new(
                "expired-access".to_owned(),
                "invalid-refresh".to_owned(),
                Timestamp::from_unix_millis(0),
                "private@example.com".to_owned(),
            )
            .unwrap(),
        )
        .unwrap();
    let handle = spawn_authorization(
        CredentialRepository::new(secrets),
        Arc::new(RefreshingTransport {
            result: Err(AuthorizationTransportError::RefreshRequired),
        }),
        Arc::new(UnexpectedBrowser),
        FixedRandom,
    );

    assert_eq!(
        handle.wait_until_restored().await,
        AuthorizationStatus::RefreshRequired
    );
    assert!(matches!(
        handle.authorized_credential().await,
        Err(AuthorizationTransportError::RefreshRequired)
    ));
}

#[tokio::test]
async fn cancellation_aborts_startup_refresh_within_one_second() {
    let secrets = FakeSecrets::default();
    CredentialRepository::new(secrets.clone())
        .persist(
            &CredentialBundle::new(
                "expired-access".to_owned(),
                "refresh-secret".to_owned(),
                Timestamp::from_unix_millis(0),
                "private@example.com".to_owned(),
            )
            .unwrap(),
        )
        .unwrap();
    let handle = spawn_authorization(
        CredentialRepository::new(secrets),
        Arc::new(PendingRefreshTransport),
        Arc::new(UnexpectedBrowser),
        FixedRandom,
    );

    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(1), handle.cancel())
        .await
        .expect("refresh cancellation completes within one second")
        .unwrap();
    assert_eq!(cancelled, AuthorizationStatus::Cancelled);
    assert_eq!(handle.status(), AuthorizationStatus::Cancelled);
}

#[tokio::test]
async fn fake_provider_journey_persists_then_publishes_connected() {
    let secrets = FakeSecrets::default();
    let repository = CredentialRepository::new(secrets.clone());
    let handle = spawn_authorization(
        repository,
        Arc::new(SuccessfulTransport),
        Arc::new(CallbackBrowser),
        FixedRandom,
    );
    assert_eq!(
        handle.wait_until_restored().await,
        AuthorizationStatus::Disconnected
    );

    assert_eq!(handle.begin().await.unwrap(), AuthorizationStatus::Starting);
    let mut statuses = handle.subscribe();
    while *statuses.borrow_and_update() != AuthorizationStatus::Connected {
        statuses.changed().await.expect("runtime remains active");
    }

    let restored = CredentialRepository::new(secrets)
        .restore()
        .unwrap()
        .expect("credentials persisted before connected");
    assert_eq!(restored.mailbox_identity(), "person@example.com");
    assert!(!format!("{restored:?}").contains("person@example.com"));
}

#[tokio::test]
async fn cancellation_aborts_inflight_exchange_and_publishes_within_one_second() {
    let handle = spawn_authorization(
        CredentialRepository::new(FakeSecrets::default()),
        Arc::new(PendingTransport),
        Arc::new(CallbackBrowser),
        FixedRandom,
    );
    handle.wait_until_restored().await;
    handle.begin().await.unwrap();
    let mut statuses = handle.subscribe();
    while *statuses.borrow_and_update() != AuthorizationStatus::Exchanging {
        statuses.changed().await.expect("runtime remains active");
    }

    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(1), handle.cancel())
        .await
        .expect("cancel completes within one second")
        .unwrap();

    assert_eq!(cancelled, AuthorizationStatus::Cancelled);
    assert_eq!(handle.status(), AuthorizationStatus::Cancelled);
}

#[tokio::test]
async fn disconnect_deletes_before_publication_and_allows_clean_reauthorization() {
    let secrets = FakeSecrets::default();
    let handle = spawn_authorization(
        CredentialRepository::new(secrets.clone()),
        Arc::new(SuccessfulTransport),
        Arc::new(CallbackBrowser),
        FixedRandom,
    );
    handle.wait_until_restored().await;

    for expected in ["first connection", "clean reauthorization"] {
        handle.begin().await.unwrap();
        let mut statuses = handle.subscribe();
        while *statuses.borrow_and_update() != AuthorizationStatus::Connected {
            statuses.changed().await.expect("runtime remains active");
        }
        assert!(
            CredentialRepository::new(secrets.clone())
                .restore()
                .unwrap()
                .is_some(),
            "{expected}"
        );

        if expected == "first connection" {
            assert_eq!(
                handle.disconnect().await.unwrap(),
                AuthorizationStatus::Disconnected
            );
            assert!(
                CredentialRepository::new(secrets.clone())
                    .restore()
                    .unwrap()
                    .is_none(),
                "disconnected is published only after verified deletion"
            );
        }
    }
}

#[tokio::test]
async fn failed_keychain_deletion_never_publishes_false_disconnected() {
    let secrets = FakeSecrets::default();
    let credentials = CredentialBundle::new(
        "access".to_owned(),
        "refresh".to_owned(),
        Timestamp::from_unix_millis(i64::MAX),
        "person@example.com".to_owned(),
    )
    .unwrap();
    CredentialRepository::new(secrets.clone())
        .persist(&credentials)
        .unwrap();
    secrets
        .fail_deletes
        .store(true, std::sync::atomic::Ordering::Release);
    let handle = spawn_authorization(
        CredentialRepository::new(secrets.clone()),
        Arc::new(SuccessfulTransport),
        Arc::new(CallbackBrowser),
        FixedRandom,
    );
    assert_eq!(
        handle.wait_until_restored().await,
        AuthorizationStatus::Connected
    );

    assert_eq!(
        handle.disconnect().await,
        Err(AuthorizationTransportError::Unavailable)
    );
    assert_eq!(
        handle.status(),
        AuthorizationStatus::CredentialStoreUnavailable
    );
    assert!(CredentialRepository::new(secrets)
        .restore()
        .unwrap()
        .is_some());
}
