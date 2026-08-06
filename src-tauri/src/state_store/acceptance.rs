//! Atomic Message acceptance over the encrypted snapshot durability boundary.

use serde::{Deserialize, Serialize};

use crate::{
    clock::Timestamp,
    ports::RandomSource,
    settings::{
        AcceptancePolicySnapshot, AcceptancePolicyWriter, CommittedSettingsSnapshot,
        SettingsSnapshot, SettingsWriteError,
    },
};

use super::{
    history::{
        History, HistoryEntry, HistoryEntryId, HistoryProvider, HistoryRetention,
        InvalidHistoryEntry, SourceMessageDigest,
    },
    outbox::{EffectIntentId, EffectKind, EffectOutbox, InvalidEffectIntent},
    seen_messages::{SeenMessageDecision, SeenMessageIdentity, SeenMessageLedger},
    AtomicStateStore, BarrierRetryOutcome, CommitOutcome, LoadedStartup, RecoveryReason, Snapshot,
    StateKey,
};

/// Narrow durability port. Production delegates directly to [`AtomicStateStore`].
pub trait AcceptanceCommitPort {
    fn commit(&mut self, snapshot: Snapshot) -> CommitOutcome;
    fn retry_barrier(&mut self) -> BarrierRetryOutcome;
}

/// Production adapter retaining the encryption key and random source with the store owner.
pub struct EncryptedAcceptanceCommitPort<R> {
    store: AtomicStateStore,
    key: StateKey,
    random: R,
}

impl<R> EncryptedAcceptanceCommitPort<R> {
    pub fn new(store: AtomicStateStore, key: StateKey, random: R) -> Self {
        Self { store, key, random }
    }

    pub fn store(&self) -> &AtomicStateStore {
        &self.store
    }
}

impl<R: RandomSource> AcceptanceCommitPort for EncryptedAcceptanceCommitPort<R> {
    fn commit(&mut self, snapshot: Snapshot) -> CommitOutcome {
        self.store.commit(snapshot, &self.key, &mut self.random)
    }

    fn retry_barrier(&mut self) -> BarrierRetryOutcome {
        self.store.retry_barrier(&self.key)
    }
}

/// One classified Message proposed for all-or-nothing acceptance.
pub struct DetectedMessageAcceptance {
    seen_identity: SeenMessageIdentity,
    history_entry: HistoryEntry,
}

impl DetectedMessageAcceptance {
    pub const fn new(seen_identity: SeenMessageIdentity, history_entry: HistoryEntry) -> Self {
        Self {
            seen_identity,
            history_entry,
        }
    }
}

/// Current-process publication released only by a verified expected-new commit.
pub struct AcceptedMessage {
    history_entry: HistoryEntry,
    retained_in_history: bool,
    effect_intents: Vec<(EffectIntentId, EffectKind)>,
}

impl AcceptedMessage {
    pub fn code(&self) -> &str {
        self.history_entry.code()
    }

    pub const fn retained_in_history(&self) -> bool {
        self.retained_in_history
    }

    pub fn effect_intents(&self) -> &[(EffectIntentId, EffectKind)] {
        &self.effect_intents
    }
}

/// Observable result of accepting one Message.
pub enum AcceptanceOutcome {
    Committed(AcceptedMessage),
    AlreadySeen,
    Uncommitted,
    BarrierPending,
    RecoveryRequired(RecoveryReason),
    Blocked,
    Rejected(AcceptanceRejection),
}

/// Result of resolving a same-process failed durability barrier.
pub enum AcceptanceBarrierOutcome {
    Committed(AcceptedMessage),
    SettingsCommitted(CommittedSettingsSnapshot),
    StartupReady,
    HistoryCleared,
    StillPending,
    RecoveryRequired(RecoveryReason),
    NotPending,
}

/// Observable result of durably clearing every History record.
pub enum HistoryClearOutcome {
    /// The clear committed, or History was already empty.
    Cleared,
    /// Failure happened before replace; the clear did not commit.
    Uncommitted,
    /// Replace succeeded but the parent-directory durability barrier failed.
    BarrierPending,
    /// The store entered a read-only recovery state.
    RecoveryRequired(RecoveryReason),
    /// An unresolved barrier blocks further mutation.
    Blocked,
    /// The proposal violates a pre-I/O model constraint.
    Rejected(AcceptanceRejection),
}

/// Pre-I/O acceptance model rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceRejection {
    RevisionOverflow,
    PolicyRevisionMismatch,
    InvalidEffectMetadata,
    Serialization,
    Storage,
}

#[derive(Clone)]
struct AcceptanceModel {
    revision: u64,
    written_at: Timestamp,
    history: History,
    seen: SeenMessageLedger,
    outbox: EffectOutbox,
    settings: serde_json::Value,
}

impl AcceptanceModel {
    fn empty() -> Self {
        Self {
            revision: 0,
            written_at: Timestamp::from_unix_millis(0),
            history: History::restore(
                HistoryRetention::SevenDays,
                Vec::<HistoryEntry>::new(),
                Timestamp::from_unix_millis(0),
            ),
            seen: SeenMessageLedger::default(),
            outbox: EffectOutbox::default(),
            settings: serde_json::Value::Null,
        }
    }

    fn snapshot(&self) -> Result<Snapshot, AcceptanceRejection> {
        let history = self
            .history
            .entries()
            .iter()
            .map(PersistedHistoryEntry::from)
            .collect();
        let document = PersistedAcceptanceDocument {
            schema_version: 1,
            written_at: self.written_at,
            history,
            seen_messages: self.seen.entries(),
            effect_outbox: &self.outbox,
            settings: &self.settings,
        };
        serde_json::to_vec(&document)
            .map(|payload| Snapshot::new(self.revision, payload))
            .map_err(|_| AcceptanceRejection::Serialization)
    }
}

#[derive(Serialize)]
struct PersistedAcceptanceDocument<'a> {
    schema_version: u32,
    written_at: Timestamp,
    history: Vec<PersistedHistoryEntry<'a>>,
    seen_messages: &'a [super::seen_messages::SeenMessage],
    effect_outbox: &'a EffectOutbox,
    settings: &'a serde_json::Value,
}

#[derive(Serialize)]
struct PersistedHistoryEntry<'a> {
    id: &'a str,
    code: &'a str,
    message_origin_display: &'a str,
    provider: PersistedProvider<'a>,
    received_at: Timestamp,
    source_message_digest: &'a str,
}

impl<'a> From<&'a HistoryEntry> for PersistedHistoryEntry<'a> {
    fn from(entry: &'a HistoryEntry) -> Self {
        Self {
            id: entry.id().as_str(),
            code: entry.code(),
            message_origin_display: entry.message_origin_display(),
            provider: PersistedProvider {
                key: entry.provider().key(),
                display: entry.provider().display(),
            },
            received_at: entry.received_at(),
            source_message_digest: entry.source_message_digest().as_str(),
        }
    }
}

#[derive(Serialize)]
struct PersistedProvider<'a> {
    key: &'a str,
    display: &'a str,
}

#[derive(Deserialize)]
struct RestoredAcceptanceDocument {
    schema_version: u32,
    written_at: Timestamp,
    history: Vec<RestoredHistoryEntry>,
    seen_messages: Vec<super::seen_messages::SeenMessage>,
    #[serde(default)]
    effect_outbox: EffectOutbox,
    settings: serde_json::Value,
}

#[derive(Deserialize)]
struct RestoredHistoryEntry {
    id: String,
    code: String,
    message_origin_display: String,
    provider: RestoredProvider,
    received_at: Timestamp,
    source_message_digest: String,
}

#[derive(Deserialize)]
struct RestoredProvider {
    key: String,
    display: String,
}

/// Authenticated payload was not a supported, internally consistent acceptance document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceRestoreError {
    UnsupportedSchema,
    InvalidDocument,
    InvalidHistory,
    InvalidPolicy,
    RevisionOverflow,
    UncommittedCancellation,
    RecoveryRequired(RecoveryReason),
    Blocked,
}

/// Startup result after canceling every live effect intent without replay.
pub enum AcceptanceStartup<S> {
    Ready(MessageAcceptance<S>),
    BarrierPending(MessageAcceptance<S>),
}

struct PendingAcceptance {
    model: AcceptanceModel,
    completion: PendingCompletion,
}

enum PendingCompletion {
    Message(AcceptedMessage),
    Settings(SettingsSnapshot),
    Startup,
    HistoryClear,
}

/// Single owner of atomic Seen/History/outbox acceptance state.
pub struct MessageAcceptance<S> {
    storage: S,
    model: AcceptanceModel,
    pending: Option<PendingAcceptance>,
}

impl<R: RandomSource> MessageAcceptance<EncryptedAcceptanceCommitPort<R>> {
    /// Starts live acceptance from an absent encrypted store.
    pub fn from_absent_store(store: AtomicStateStore, key: StateKey, random: R) -> Self {
        Self::empty(EncryptedAcceptanceCommitPort::new(store, key, random))
    }

    /// Consumes authenticated startup state and enforces durable effect cancellation.
    pub fn restore_loaded(
        loaded: LoadedStartup,
        key: StateKey,
        random: R,
        now: Timestamp,
    ) -> Result<AcceptanceStartup<EncryptedAcceptanceCommitPort<R>>, AcceptanceRestoreError> {
        let snapshot = loaded.snapshot().clone();
        let store = loaded.into_store_for_effect_cancellation();
        Self::restore_after_restart(
            EncryptedAcceptanceCommitPort::new(store, key, random),
            &snapshot,
            now,
        )
    }
}

impl<S: AcceptanceCommitPort> MessageAcceptance<S> {
    /// Starts with an absent encrypted snapshot.
    pub fn empty(storage: S) -> Self {
        Self {
            storage,
            model: AcceptanceModel::empty(),
            pending: None,
        }
    }

    /// Restores one authenticated survivor and durably cancels live effect metadata.
    ///
    /// No effect payload is accepted by this API, so restart cannot replay one.
    pub fn restore_after_restart(
        storage: S,
        snapshot: &Snapshot,
        now: Timestamp,
    ) -> Result<AcceptanceStartup<S>, AcceptanceRestoreError> {
        let restored: RestoredAcceptanceDocument = serde_json::from_slice(snapshot.payload())
            .map_err(|_| AcceptanceRestoreError::InvalidDocument)?;
        if restored.schema_version != 1 {
            return Err(AcceptanceRestoreError::UnsupportedSchema);
        }
        let retention = restored_retention(&restored.settings)?;
        let history_entries = restored
            .history
            .into_iter()
            .map(restored_history_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let mut model = AcceptanceModel {
            revision: snapshot.revision(),
            written_at: restored.written_at,
            history: History::restore(retention, history_entries, now),
            seen: SeenMessageLedger::restore(restored.seen_messages, now),
            outbox: restored.effect_outbox,
            settings: restored.settings,
        };
        model.outbox.cancel_live_after_restart(now);
        let normalization_changed = model.snapshot()?.payload() != snapshot.payload();
        let mut acceptance = Self {
            storage,
            model,
            pending: None,
        };
        if !normalization_changed {
            return Ok(AcceptanceStartup::Ready(acceptance));
        }
        let Some(next_revision) = acceptance.model.revision.checked_add(1) else {
            return Err(AcceptanceRestoreError::RevisionOverflow);
        };
        acceptance.model.revision = next_revision;
        acceptance.model.written_at = now;
        let snapshot = acceptance.model.snapshot()?;
        match acceptance.storage.commit(snapshot) {
            CommitOutcome::Committed(_) => Ok(AcceptanceStartup::Ready(acceptance)),
            CommitOutcome::BarrierPending => {
                acceptance.pending = Some(PendingAcceptance {
                    model: acceptance.model.clone(),
                    completion: PendingCompletion::Startup,
                });
                Ok(AcceptanceStartup::BarrierPending(acceptance))
            }
            CommitOutcome::Uncommitted => Err(AcceptanceRestoreError::UncommittedCancellation),
            CommitOutcome::RecoveryRequired(reason) => {
                Err(AcceptanceRestoreError::RecoveryRequired(reason))
            }
            CommitOutcome::Blocked => Err(AcceptanceRestoreError::Blocked),
            CommitOutcome::Rejected(_) => Err(AcceptanceRestoreError::InvalidDocument),
        }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn seen_count(&self) -> usize {
        self.model.seen.entries().len()
    }

    pub fn history_count(&self) -> usize {
        self.model.history.entries().len()
    }

    pub fn outbox_count(&self) -> usize {
        self.model.outbox.intents().len()
    }

    /// Returns durable intents eligible for current-process dispatch.
    pub fn live_effect_count(&self) -> usize {
        self.model.outbox.live_count()
    }

    /// Returns the current durable History records, newest first.
    pub fn history_entries(&self) -> &[HistoryEntry] {
        self.model.history.entries()
    }

    /// Returns the acceptance policy committed alongside the Settings, in
    /// whichever persisted shape the writing path used. `None` means the
    /// stored projection is unreadable and callers must not guess a policy.
    pub fn acceptance_policy(&self) -> Option<AcceptancePolicySnapshot> {
        let value = self
            .model
            .settings
            .get("acceptance")
            .unwrap_or(&self.model.settings);
        serde_json::from_value(value.clone()).ok()
    }

    /// Durably removes every History record while leaving the Seen Message
    /// ledger untouched. The clear is observable only after a verified commit.
    pub fn clear_history(&mut self, now: Timestamp) -> HistoryClearOutcome {
        if self.pending.is_some() {
            return HistoryClearOutcome::Blocked;
        }
        if self.model.history.entries().is_empty() {
            return HistoryClearOutcome::Cleared;
        }
        let Some(revision) = self.model.revision.checked_add(1) else {
            return HistoryClearOutcome::Rejected(AcceptanceRejection::RevisionOverflow);
        };
        let mut proposed = self.model.clone();
        proposed.revision = revision;
        proposed.written_at = now;
        proposed.history.clear();
        let snapshot = match proposed.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return HistoryClearOutcome::Rejected(error),
        };
        match self.storage.commit(snapshot) {
            CommitOutcome::Committed(_) => {
                self.model = proposed;
                HistoryClearOutcome::Cleared
            }
            CommitOutcome::Uncommitted => HistoryClearOutcome::Uncommitted,
            CommitOutcome::BarrierPending => {
                self.pending = Some(PendingAcceptance {
                    model: proposed,
                    completion: PendingCompletion::HistoryClear,
                });
                HistoryClearOutcome::BarrierPending
            }
            CommitOutcome::RecoveryRequired(reason) => HistoryClearOutcome::RecoveryRequired(reason),
            CommitOutcome::Blocked => HistoryClearOutcome::Blocked,
            CommitOutcome::Rejected(_) => HistoryClearOutcome::Rejected(AcceptanceRejection::Storage),
        }
    }

    /// Proposes one all-or-nothing acceptance and publishes only after verification.
    pub fn accept(
        &mut self,
        request: DetectedMessageAcceptance,
        policy: &AcceptancePolicySnapshot,
        now: Timestamp,
    ) -> AcceptanceOutcome {
        if self.pending.is_some() {
            return AcceptanceOutcome::Blocked;
        }
        let mut proposed = self.model.clone();
        if proposed
            .seen
            .decision_for(&request.seen_identity, now)
            .is_some()
        {
            return AcceptanceOutcome::AlreadySeen;
        }
        let Some(revision) = proposed.revision.checked_add(1) else {
            return AcceptanceOutcome::Rejected(AcceptanceRejection::RevisionOverflow);
        };
        proposed.revision = revision;
        proposed.written_at = now;
        match persisted_policy_revision(&proposed.settings) {
            Some(revision) if revision != policy.revision() => {
                return AcceptanceOutcome::Rejected(AcceptanceRejection::PolicyRevisionMismatch);
            }
            Some(_) => {}
            None if proposed.settings.is_null() => {
                proposed.settings = match serde_json::to_value(policy) {
                    Ok(settings) => settings,
                    Err(_) => {
                        return AcceptanceOutcome::Rejected(AcceptanceRejection::Serialization);
                    }
                };
            }
            None => {
                return AcceptanceOutcome::Rejected(AcceptanceRejection::PolicyRevisionMismatch);
            }
        }
        proposed
            .history
            .set_retention(policy.history_retention(), now);
        let retained_in_history = proposed.history.record(request.history_entry.clone(), now);
        if !proposed.seen.record(
            request.seen_identity.clone(),
            SeenMessageDecision::Detected,
            now,
        ) {
            return AcceptanceOutcome::AlreadySeen;
        }

        let mut effect_intents = Vec::new();
        if policy.auto_copy_allowed_for(request.history_entry.provider().key()) {
            let intent_id =
                EffectIntentId::derive(request.seen_identity.as_str(), EffectKind::AutoCopy);
            if add_effect(
                &mut proposed.outbox,
                intent_id.clone(),
                revision,
                request.history_entry.provider().key(),
                EffectKind::AutoCopy,
                now,
            )
            .is_err()
            {
                return AcceptanceOutcome::Rejected(AcceptanceRejection::InvalidEffectMetadata);
            }
            effect_intents.push((intent_id, EffectKind::AutoCopy));
        }
        if policy.notifications_enabled() {
            let intent_id =
                EffectIntentId::derive(request.seen_identity.as_str(), EffectKind::Notification);
            if add_effect(
                &mut proposed.outbox,
                intent_id.clone(),
                revision,
                request.history_entry.provider().key(),
                EffectKind::Notification,
                now,
            )
            .is_err()
            {
                return AcceptanceOutcome::Rejected(AcceptanceRejection::InvalidEffectMetadata);
            }
            effect_intents.push((intent_id, EffectKind::Notification));
        }
        let publication = AcceptedMessage {
            history_entry: request.history_entry,
            retained_in_history,
            effect_intents,
        };
        let snapshot = match proposed.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return AcceptanceOutcome::Rejected(error),
        };
        match self.storage.commit(snapshot) {
            CommitOutcome::Committed(_) => {
                self.model = proposed;
                AcceptanceOutcome::Committed(publication)
            }
            CommitOutcome::Uncommitted => AcceptanceOutcome::Uncommitted,
            CommitOutcome::BarrierPending => {
                self.pending = Some(PendingAcceptance {
                    model: proposed,
                    completion: PendingCompletion::Message(publication),
                });
                AcceptanceOutcome::BarrierPending
            }
            CommitOutcome::RecoveryRequired(reason) => AcceptanceOutcome::RecoveryRequired(reason),
            CommitOutcome::Blocked => AcceptanceOutcome::Blocked,
            CommitOutcome::Rejected(_) => AcceptanceOutcome::Rejected(AcceptanceRejection::Storage),
        }
    }

    /// Retries only the failed parent-directory barrier; it never initiates a read.
    pub fn retry_barrier(&mut self) -> AcceptanceBarrierOutcome {
        let Some(_) = self.pending else {
            return AcceptanceBarrierOutcome::NotPending;
        };
        match self.storage.retry_barrier() {
            BarrierRetryOutcome::StillPending => AcceptanceBarrierOutcome::StillPending,
            BarrierRetryOutcome::Committed(_) => {
                let pending = self.pending.take().expect("pending checked");
                self.model = pending.model;
                match pending.completion {
                    PendingCompletion::Message(publication) => {
                        AcceptanceBarrierOutcome::Committed(publication)
                    }
                    PendingCompletion::Settings(settings) => {
                        AcceptanceBarrierOutcome::SettingsCommitted(
                            CommittedSettingsSnapshot::verified(settings),
                        )
                    }
                    PendingCompletion::Startup => AcceptanceBarrierOutcome::StartupReady,
                    PendingCompletion::HistoryClear => AcceptanceBarrierOutcome::HistoryCleared,
                }
            }
            BarrierRetryOutcome::RecoveryRequired(reason) => {
                self.pending = None;
                AcceptanceBarrierOutcome::RecoveryRequired(reason)
            }
            BarrierRetryOutcome::NotPending => AcceptanceBarrierOutcome::NotPending,
        }
    }
}

impl<S: AcceptanceCommitPort> AcceptancePolicyWriter for MessageAcceptance<S> {
    fn write_settings_and_acceptance(
        &mut self,
        expected_previous_revision: u64,
        settings: &SettingsSnapshot,
        next: &AcceptancePolicySnapshot,
        now: Timestamp,
    ) -> Result<(), SettingsWriteError> {
        if self.pending.is_some() {
            return Err(SettingsWriteError::Failed);
        }
        let installed_revision = persisted_policy_revision(&self.model.settings).unwrap_or(0);
        if installed_revision != expected_previous_revision {
            return Err(SettingsWriteError::RevisionConflict);
        }
        let Some(revision) = self.model.revision.checked_add(1) else {
            return Err(SettingsWriteError::Failed);
        };
        let mut proposed = self.model.clone();
        proposed.revision = revision;
        proposed.written_at = now;
        proposed
            .history
            .set_retention(next.history_retention(), now);
        proposed.seen.prune(now);
        proposed.outbox.expire_and_prune(now);
        proposed.settings = serde_json::json!({
            "settings": settings,
            "acceptance": next,
        });
        let snapshot = proposed
            .snapshot()
            .map_err(|_| SettingsWriteError::Failed)?;
        match self.storage.commit(snapshot) {
            CommitOutcome::Committed(_) => {
                self.model = proposed;
                Ok(())
            }
            CommitOutcome::BarrierPending => {
                self.pending = Some(PendingAcceptance {
                    model: proposed,
                    completion: PendingCompletion::Settings(settings.clone()),
                });
                Err(SettingsWriteError::Failed)
            }
            CommitOutcome::Uncommitted
            | CommitOutcome::RecoveryRequired(_)
            | CommitOutcome::Blocked
            | CommitOutcome::Rejected(_) => Err(SettingsWriteError::Failed),
        }
    }
}

impl From<AcceptanceRejection> for AcceptanceRestoreError {
    fn from(value: AcceptanceRejection) -> Self {
        match value {
            AcceptanceRejection::RevisionOverflow => Self::RevisionOverflow,
            AcceptanceRejection::PolicyRevisionMismatch => Self::InvalidPolicy,
            AcceptanceRejection::InvalidEffectMetadata
            | AcceptanceRejection::Serialization
            | AcceptanceRejection::Storage => Self::InvalidDocument,
        }
    }
}

fn restored_history_entry(
    entry: RestoredHistoryEntry,
) -> Result<HistoryEntry, AcceptanceRestoreError> {
    HistoryEntry::new(
        HistoryEntryId::new(entry.id).map_err(map_history_error)?,
        entry.code,
        entry.message_origin_display,
        HistoryProvider::new(entry.provider.key, entry.provider.display)
            .map_err(map_history_error)?,
        entry.received_at,
        SourceMessageDigest::new(entry.source_message_digest).map_err(map_history_error)?,
    )
    .map_err(map_history_error)
}

fn map_history_error(_: InvalidHistoryEntry) -> AcceptanceRestoreError {
    AcceptanceRestoreError::InvalidHistory
}

fn restored_retention(
    settings: &serde_json::Value,
) -> Result<HistoryRetention, AcceptanceRestoreError> {
    let policy = settings.get("acceptance").unwrap_or(settings);
    let days = policy
        .get("history_retention")
        .or_else(|| policy.get("history_retention_days"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|days| u8::try_from(days).ok())
        .ok_or(AcceptanceRestoreError::InvalidPolicy)?;
    HistoryRetention::try_from(days).map_err(|_| AcceptanceRestoreError::InvalidPolicy)
}

fn persisted_policy_revision(settings: &serde_json::Value) -> Option<u64> {
    let policy = settings.get("acceptance").unwrap_or(settings);
    policy
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| policy.get("history_retention_days").is_some().then_some(0))
}

fn add_effect(
    outbox: &mut EffectOutbox,
    id: EffectIntentId,
    revision: u64,
    provider: &str,
    kind: EffectKind,
    now: Timestamp,
) -> Result<(), InvalidEffectIntent> {
    outbox.add_pending(id, revision, provider, kind, now)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crate::{
        clock::Timestamp,
        settings::{
            AcceptancePolicySnapshot, AcceptancePolicyWriter, Settings, SettingsChange,
            SettingsError, SettingsSnapshot, SettingsWriteError,
        },
        state_store::{
            history::{HistoryEntry, HistoryEntryId, HistoryProvider, SourceMessageDigest},
            seen_messages::SeenMessageIdentity,
            CommitOutcome, Snapshot, SnapshotIdentity,
        },
    };

    use super::{
        AcceptanceBarrierOutcome, AcceptanceCommitPort, AcceptanceOutcome, AcceptanceStartup,
        DetectedMessageAcceptance, HistoryClearOutcome, MessageAcceptance,
    };

    struct AcceptSettings;

    impl AcceptancePolicyWriter for AcceptSettings {
        fn write_settings_and_acceptance(
            &mut self,
            _expected_previous_revision: u64,
            _settings: &SettingsSnapshot,
            _next: &AcceptancePolicySnapshot,
            _now: Timestamp,
        ) -> Result<(), SettingsWriteError> {
            Ok(())
        }
    }

    struct FakeCommitPort {
        outcomes: VecDeque<CommitOutcome>,
        retries: VecDeque<crate::state_store::BarrierRetryOutcome>,
        proposed: Vec<Snapshot>,
        retry_calls: usize,
    }

    impl AcceptanceCommitPort for FakeCommitPort {
        fn commit(&mut self, snapshot: Snapshot) -> CommitOutcome {
            self.proposed.push(snapshot);
            self.outcomes.pop_front().unwrap()
        }

        fn retry_barrier(&mut self) -> crate::state_store::BarrierRetryOutcome {
            self.retry_calls += 1;
            self.retries.pop_front().unwrap()
        }
    }

    fn request() -> DetectedMessageAcceptance {
        DetectedMessageAcceptance::new(
            SeenMessageIdentity::new("a".repeat(64)).unwrap(),
            HistoryEntry::new(
                HistoryEntryId::new("history-1").unwrap(),
                "123456",
                "Example sender",
                HistoryProvider::new("example", "Example").unwrap(),
                Timestamp::from_unix_millis(1_000),
                SourceMessageDigest::new("b".repeat(64)).unwrap(),
            )
            .unwrap(),
        )
    }

    fn second_request() -> DetectedMessageAcceptance {
        DetectedMessageAcceptance::new(
            SeenMessageIdentity::new("c".repeat(64)).unwrap(),
            HistoryEntry::new(
                HistoryEntryId::new("history-2").unwrap(),
                "654321",
                "Second sender",
                HistoryProvider::new("second", "Second").unwrap(),
                Timestamp::from_unix_millis(2_000),
                SourceMessageDigest::new("d".repeat(64)).unwrap(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn verified_commit_is_the_only_path_that_publishes_an_atomic_acceptance() {
        let expected = Snapshot::new(1, Vec::new());
        let identity = SnapshotIdentity::from_snapshot(&expected);
        let port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let policy = AcceptancePolicySnapshot::from(Settings::new().snapshot());
        let mut acceptance = MessageAcceptance::empty(port);

        let outcome = acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000));

        let AcceptanceOutcome::Committed(published) = outcome else {
            panic!("verified commit must publish");
        };
        assert_eq!(published.code(), "123456");
        assert!(published.retained_in_history());
        assert_eq!(acceptance.seen_count(), 1);
        assert_eq!(acceptance.history_count(), 1);
        assert_eq!(acceptance.outbox_count(), 0);
        assert_eq!(acceptance.storage().proposed.len(), 1);
    }

    #[test]
    fn clear_history_commits_an_empty_history_and_keeps_the_seen_ledger() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let port = FakeCommitPort {
            outcomes: VecDeque::from([
                CommitOutcome::Committed(identity),
                CommitOutcome::Committed(identity),
                CommitOutcome::Committed(identity),
            ]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let policy = AcceptancePolicySnapshot::from(Settings::new().snapshot());
        let mut acceptance = MessageAcceptance::empty(port);

        acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000));
        acceptance.accept(second_request(), &policy, Timestamp::from_unix_millis(2_000));

        assert_eq!(acceptance.history_entries().len(), 2);
        assert_eq!(acceptance.history_entries()[0].id().as_str(), "history-2");
        assert_eq!(acceptance.history_entries()[1].id().as_str(), "history-1");

        assert!(matches!(
            acceptance.clear_history(Timestamp::from_unix_millis(3_000)),
            HistoryClearOutcome::Cleared
        ));
        assert!(acceptance.history_entries().is_empty());
        assert_eq!(acceptance.history_count(), 0);
        assert_eq!(acceptance.seen_count(), 2);

        assert!(matches!(
            acceptance.clear_history(Timestamp::from_unix_millis(4_000)),
            HistoryClearOutcome::Cleared
        ));
        assert_eq!(acceptance.storage().proposed.len(), 3);
    }

    #[test]
    fn clear_history_releases_no_partial_state_while_its_barrier_is_pending() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity), CommitOutcome::BarrierPending]),
            retries: VecDeque::from([crate::state_store::BarrierRetryOutcome::Committed(identity)]),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let policy = AcceptancePolicySnapshot::from(Settings::new().snapshot());
        let mut acceptance = MessageAcceptance::empty(port);

        acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000));
        assert!(matches!(
            acceptance.clear_history(Timestamp::from_unix_millis(2_000)),
            HistoryClearOutcome::BarrierPending
        ));
        assert_eq!(acceptance.history_count(), 1);
        assert!(matches!(
            acceptance.clear_history(Timestamp::from_unix_millis(2_001)),
            HistoryClearOutcome::Blocked
        ));

        assert!(matches!(
            acceptance.retry_barrier(),
            AcceptanceBarrierOutcome::HistoryCleared
        ));
        assert!(acceptance.history_entries().is_empty());
    }

    #[test]
    fn pre_replace_failure_is_uncommitted_with_no_partial_state_or_publication() {
        let port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Uncommitted]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let policy = AcceptancePolicySnapshot::from(Settings::new().snapshot());
        let mut acceptance = MessageAcceptance::empty(port);

        assert!(matches!(
            acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
            AcceptanceOutcome::Uncommitted
        ));
        assert_eq!(acceptance.seen_count(), 0);
        assert_eq!(acceptance.history_count(), 0);
        assert_eq!(acceptance.outbox_count(), 0);
    }

    #[test]
    fn failed_post_replace_barrier_blocks_publication_until_retry_fsync_and_verification() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let port = FakeCommitPort {
            outcomes: VecDeque::from([
                CommitOutcome::BarrierPending,
                CommitOutcome::Committed(identity),
            ]),
            retries: VecDeque::from([
                crate::state_store::BarrierRetryOutcome::StillPending,
                crate::state_store::BarrierRetryOutcome::Committed(identity),
            ]),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let policy = AcceptancePolicySnapshot::from(Settings::new().snapshot());
        let mut acceptance = MessageAcceptance::empty(port);

        assert!(matches!(
            acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
            AcceptanceOutcome::BarrierPending
        ));
        assert_eq!(acceptance.seen_count(), 0);
        assert_eq!(acceptance.history_count(), 0);
        assert!(matches!(
            acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_001)),
            AcceptanceOutcome::Blocked
        ));
        assert!(matches!(
            acceptance.retry_barrier(),
            AcceptanceBarrierOutcome::StillPending
        ));
        assert_eq!(acceptance.seen_count(), 0);

        let AcceptanceBarrierOutcome::Committed(published) = acceptance.retry_barrier() else {
            panic!("successful retry and verification must release publication");
        };
        assert_eq!(published.code(), "123456");
        assert_eq!(acceptance.seen_count(), 1);
        assert_eq!(acceptance.history_count(), 1);
        assert_eq!(acceptance.storage().retry_calls, 2);
    }

    #[test]
    fn successful_original_barrier_with_any_non_expected_readback_enters_recovery() {
        for reason in [
            crate::state_store::RecoveryReason::Missing,
            crate::state_store::RecoveryReason::AuthenticationFailed,
            crate::state_store::RecoveryReason::UnexpectedSnapshot,
        ] {
            let port = FakeCommitPort {
                outcomes: VecDeque::from([CommitOutcome::RecoveryRequired(reason)]),
                retries: VecDeque::new(),
                proposed: Vec::new(),
                retry_calls: 0,
            };
            let policy = AcceptancePolicySnapshot::from(Settings::new().snapshot());
            let mut acceptance = MessageAcceptance::empty(port);

            assert!(matches!(
                acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
                AcceptanceOutcome::RecoveryRequired(observed) if observed == reason
            ));
            assert_eq!(acceptance.seen_count(), 0);
            assert_eq!(acceptance.history_count(), 0);
            assert_eq!(acceptance.outbox_count(), 0);
        }
    }

    #[test]
    fn history_off_still_commits_seen_and_publishes_only_to_the_current_session() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let mut settings = Settings::new();
        settings
            .apply(
                SettingsChange::SetHistoryRetentionDays(0),
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        let policy = AcceptancePolicySnapshot::from(settings.snapshot());
        let mut acceptance = MessageAcceptance::empty(port);

        let AcceptanceOutcome::Committed(published) =
            acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000))
        else {
            panic!("History Off acceptance must still commit");
        };
        assert_eq!(published.code(), "123456");
        assert!(!published.retained_in_history());
        assert_eq!(acceptance.seen_count(), 1);
        assert_eq!(acceptance.history_count(), 0);
    }

    #[test]
    fn restart_with_new_survivor_cancels_payload_free_intents_and_never_reaccepts() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let first_port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let mut settings = Settings::new();
        settings
            .apply(
                SettingsChange::GrantAutoCopyConsent,
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        settings
            .apply(
                SettingsChange::SetAutoCopyEnabled(true),
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        let policy = AcceptancePolicySnapshot::from(settings.snapshot());
        let mut first_run = MessageAcceptance::empty(first_port);
        assert!(matches!(
            first_run.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
            AcceptanceOutcome::Committed(_)
        ));
        assert_eq!(first_run.live_effect_count(), 1);
        let surviving_new = first_run.storage().proposed[0].clone();
        let document: serde_json::Value = serde_json::from_slice(surviving_new.payload()).unwrap();
        let durable_effects = serde_json::to_string(&document["effect_outbox"]).unwrap();
        assert!(!durable_effects.contains("123456"));
        assert!(!durable_effects.contains("payload"));

        let restart_port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let AcceptanceStartup::Ready(mut restarted) = MessageAcceptance::restore_after_restart(
            restart_port,
            &surviving_new,
            Timestamp::from_unix_millis(2_000),
        )
        .unwrap() else {
            panic!("effect cancellation commit must activate startup");
        };
        assert_eq!(restarted.live_effect_count(), 0);
        assert_eq!(restarted.seen_count(), 1);
        assert!(matches!(
            restarted.accept(request(), &policy, Timestamp::from_unix_millis(2_001)),
            AcceptanceOutcome::AlreadySeen
        ));
    }

    #[test]
    fn crash_before_barrier_retry_with_prior_survivor_may_accept_the_message_again() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let first_port = FakeCommitPort {
            outcomes: VecDeque::from([
                CommitOutcome::Committed(identity),
                CommitOutcome::BarrierPending,
            ]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let policy = AcceptancePolicySnapshot::from(Settings::new().snapshot());
        let mut first_process = MessageAcceptance::empty(first_port);
        assert!(matches!(
            first_process.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
            AcceptanceOutcome::Committed(_)
        ));
        let surviving_prior = first_process.storage().proposed[0].clone();
        assert!(matches!(
            first_process.accept(
                second_request(),
                &policy,
                Timestamp::from_unix_millis(2_000)
            ),
            AcceptanceOutcome::BarrierPending
        ));

        let restart_port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let AcceptanceStartup::Ready(mut restarted) = MessageAcceptance::restore_after_restart(
            restart_port,
            &surviving_prior,
            Timestamp::from_unix_millis(3_000),
        )
        .unwrap() else {
            panic!("prior survivor has no live effects");
        };
        assert!(matches!(
            restarted.accept(
                second_request(),
                &policy,
                Timestamp::from_unix_millis(3_001)
            ),
            AcceptanceOutcome::Committed(_)
        ));
    }

    #[test]
    fn unreadable_restart_survivor_never_activates_acceptance_or_effects() {
        let unreadable = Snapshot::new(1, b"{not-valid-json".to_vec());
        let port = FakeCommitPort {
            outcomes: VecDeque::new(),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };

        assert!(matches!(
            MessageAcceptance::restore_after_restart(
                port,
                &unreadable,
                Timestamp::from_unix_millis(3_000)
            ),
            Err(super::AcceptanceRestoreError::InvalidDocument)
        ));
    }

    #[test]
    fn restart_effect_cancellation_remains_blocked_until_its_barrier_retry_commits() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let first_port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let mut settings = Settings::new();
        settings
            .apply(
                SettingsChange::GrantAutoCopyConsent,
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        settings
            .apply(
                SettingsChange::SetAutoCopyEnabled(true),
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        let policy = AcceptancePolicySnapshot::from(settings.snapshot());
        let mut first_run = MessageAcceptance::empty(first_port);
        assert!(matches!(
            first_run.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
            AcceptanceOutcome::Committed(_)
        ));
        let surviving_new = first_run.storage().proposed[0].clone();

        let restart_port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::BarrierPending]),
            retries: VecDeque::from([
                crate::state_store::BarrierRetryOutcome::StillPending,
                crate::state_store::BarrierRetryOutcome::Committed(identity),
            ]),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let AcceptanceStartup::BarrierPending(mut restarting) =
            MessageAcceptance::restore_after_restart(
                restart_port,
                &surviving_new,
                Timestamp::from_unix_millis(2_000),
            )
            .unwrap()
        else {
            panic!("failed cancellation barrier must block startup");
        };
        assert!(matches!(
            restarting.accept(
                second_request(),
                &policy,
                Timestamp::from_unix_millis(2_001)
            ),
            AcceptanceOutcome::Blocked
        ));
        assert!(matches!(
            restarting.retry_barrier(),
            AcceptanceBarrierOutcome::StillPending
        ));
        assert!(matches!(
            restarting.retry_barrier(),
            AcceptanceBarrierOutcome::StartupReady
        ));
        assert_eq!(restarting.live_effect_count(), 0);
    }

    #[test]
    fn restart_persists_history_seen_and_terminal_outbox_pruning_before_intake() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let first_port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let mut settings = Settings::new();
        settings
            .apply(
                SettingsChange::GrantAutoCopyConsent,
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        settings
            .apply(
                SettingsChange::SetAutoCopyEnabled(true),
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        let policy = AcceptancePolicySnapshot::from(settings.snapshot());
        let mut first_run = MessageAcceptance::empty(first_port);
        assert!(matches!(
            first_run.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
            AcceptanceOutcome::Committed(_)
        ));
        let mut document: serde_json::Value =
            serde_json::from_slice(first_run.storage().proposed[0].payload()).unwrap();
        document["effect_outbox"][0]["state"] = serde_json::json!("completed");
        document["effect_outbox"][0]["outcome"] = serde_json::json!("succeeded");
        let survivor = Snapshot::new(1, serde_json::to_vec(&document).unwrap());

        let restart_port = FakeCommitPort {
            outcomes: VecDeque::from([CommitOutcome::Committed(identity)]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let restart_time = Timestamp::from_unix_millis(31 * 24 * 60 * 60 * 1_000 + 1_000);
        let AcceptanceStartup::Ready(restarted) =
            MessageAcceptance::restore_after_restart(restart_port, &survivor, restart_time)
                .unwrap()
        else {
            panic!("normalization commit must verify before startup");
        };
        assert_eq!(restarted.history_count(), 0);
        assert_eq!(restarted.seen_count(), 0);
        assert_eq!(restarted.outbox_count(), 0);
        assert_eq!(restarted.storage().proposed.len(), 1);
        assert_eq!(restarted.storage().proposed[0].revision(), 2);
    }

    #[test]
    fn settings_policy_never_reports_success_across_an_indeterminate_barrier() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let port = FakeCommitPort {
            outcomes: VecDeque::from([
                CommitOutcome::BarrierPending,
                CommitOutcome::Committed(identity),
            ]),
            retries: VecDeque::from([crate::state_store::BarrierRetryOutcome::Committed(identity)]),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let mut acceptance = MessageAcceptance::empty(port);
        let mut settings = Settings::new();

        assert_eq!(
            settings.apply(
                SettingsChange::GrantAutoCopyConsent,
                Timestamp::from_unix_millis(1_000),
                &mut acceptance
            ),
            Err(SettingsError::PersistenceFailed)
        );
        assert_eq!(settings.snapshot().revision(), 0);
        assert!(matches!(
            acceptance.accept(
                request(),
                &AcceptancePolicySnapshot::from(settings.snapshot()),
                Timestamp::from_unix_millis(1_000)
            ),
            AcceptanceOutcome::Blocked
        ));
        let AcceptanceBarrierOutcome::SettingsCommitted(committed) = acceptance.retry_barrier()
        else {
            panic!("verified Settings retry must carry reconciliation proof");
        };
        settings.reconcile_committed(committed);
        assert_eq!(settings.snapshot().revision(), 1);
        assert!(matches!(
            acceptance.accept(
                request(),
                &AcceptancePolicySnapshot::from(settings.snapshot()),
                Timestamp::from_unix_millis(1_001)
            ),
            AcceptanceOutcome::Committed(_)
        ));
    }

    #[test]
    fn settings_policy_commit_uses_authoritative_time_and_prunes_all_acceptance_domains() {
        let identity = SnapshotIdentity::from_snapshot(&Snapshot::new(1, Vec::new()));
        let port = FakeCommitPort {
            outcomes: VecDeque::from([
                CommitOutcome::Committed(identity),
                CommitOutcome::Committed(identity),
            ]),
            retries: VecDeque::new(),
            proposed: Vec::new(),
            retry_calls: 0,
        };
        let mut settings = Settings::new();
        settings
            .apply(
                SettingsChange::GrantAutoCopyConsent,
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        settings
            .apply(
                SettingsChange::SetAutoCopyEnabled(true),
                Timestamp::from_unix_millis(500),
                &mut AcceptSettings,
            )
            .unwrap();
        let policy = AcceptancePolicySnapshot::from(settings.snapshot());
        let mut acceptance = MessageAcceptance::empty(port);
        assert!(matches!(
            acceptance.accept(request(), &policy, Timestamp::from_unix_millis(1_000)),
            AcceptanceOutcome::Committed(_)
        ));

        let update_time = Timestamp::from_unix_millis(31 * 24 * 60 * 60 * 1_000 + 1_000);
        settings
            .apply(
                SettingsChange::RevokeAutoCopyConsent,
                update_time,
                &mut acceptance,
            )
            .unwrap();

        let document: serde_json::Value =
            serde_json::from_slice(acceptance.storage().proposed[1].payload()).unwrap();
        assert_eq!(document["written_at"], serde_json::json!(update_time));
        assert_eq!(document["history"], serde_json::json!([]));
        assert_eq!(document["seen_messages"], serde_json::json!([]));
        assert_eq!(document["effect_outbox"][0]["state"], "expired");
    }
}
