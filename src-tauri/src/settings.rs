//! Validated Settings and acceptance-policy synchronization boundary.
//!
//! This module owns no Tauri command and performs no file I/O itself.  A
//! caller supplies the atomic encrypted acceptance-snapshot writer; Settings
//! does not report a change until that writer accepts the next policy revision.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::state_store::history::HistoryRetention;

/// Explicit user authorization for automatic copying.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoCopyConsent {
    /// No affirmative automatic-copy decision exists.
    #[default]
    Unknown,
    /// The user explicitly consented to automatic copying.
    Granted,
    /// The user explicitly declined automatic copying.
    Declined,
}

/// Observed notification permission, owned more fully by Task 14.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPermission {
    /// Permission has not been requested yet.
    #[default]
    Unknown,
    /// The operating system granted permission.
    Granted,
    /// The operating system denied permission.
    Denied,
}

/// Product-approved clipboard lease choices expressed in seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum ClipboardLeaseSeconds {
    /// Fifteen seconds.
    Fifteen,
    /// Thirty seconds, the product default.
    #[default]
    Thirty,
    /// Sixty seconds.
    Sixty,
}

impl TryFrom<u8> for ClipboardLeaseSeconds {
    type Error = SettingsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            15 => Ok(Self::Fifteen),
            30 => Ok(Self::Thirty),
            60 => Ok(Self::Sixty),
            _ => Err(SettingsError::InvalidLeaseSeconds),
        }
    }
}

impl From<ClipboardLeaseSeconds> for u8 {
    fn from(value: ClipboardLeaseSeconds) -> Self {
        match value {
            ClipboardLeaseSeconds::Fifteen => 15,
            ClipboardLeaseSeconds::Thirty => 30,
            ClipboardLeaseSeconds::Sixty => 60,
        }
    }
}

/// Settings persisted by the pre-v2 application.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyAutoCopySettings {
    /// The old enabled toggle; it was not recorded consent.
    pub auto_copy_enabled: bool,
}

/// The stable settings accepted by the UI after a successful update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsSnapshot {
    revision: u64,
    history_retention: HistoryRetention,
    clipboard_lease: ClipboardLeaseSeconds,
    auto_copy_consent: AutoCopyConsent,
    auto_copy_enabled: bool,
    provider_overrides: BTreeMap<String, bool>,
    notifications_enabled: bool,
    notification_permission: NotificationPermission,
    start_at_login: bool,
}

/// Raw settings decoded from the encrypted snapshot before reconciliation.
///
/// It is intentionally distinct from [`SettingsSnapshot`]: decoding alone is
/// not proof that notification, consent, or override invariants hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSettings {
    revision: u64,
    history_retention: HistoryRetention,
    clipboard_lease: ClipboardLeaseSeconds,
    auto_copy_consent: AutoCopyConsent,
    auto_copy_enabled: bool,
    provider_overrides: BTreeMap<String, bool>,
    notifications_enabled: bool,
    notification_permission: NotificationPermission,
    start_at_login: bool,
}

impl From<&SettingsSnapshot> for PersistedSettings {
    fn from(value: &SettingsSnapshot) -> Self {
        Self {
            revision: value.revision,
            history_retention: value.history_retention,
            clipboard_lease: value.clipboard_lease,
            auto_copy_consent: value.auto_copy_consent,
            auto_copy_enabled: value.auto_copy_enabled,
            provider_overrides: value.provider_overrides.clone(),
            notifications_enabled: value.notifications_enabled,
            notification_permission: value.notification_permission,
            start_at_login: value.start_at_login,
        }
    }
}

impl Default for SettingsSnapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            history_retention: HistoryRetention::SevenDays,
            clipboard_lease: ClipboardLeaseSeconds::Thirty,
            auto_copy_consent: AutoCopyConsent::Unknown,
            auto_copy_enabled: false,
            provider_overrides: BTreeMap::new(),
            notifications_enabled: false,
            notification_permission: NotificationPermission::Unknown,
            start_at_login: false,
        }
    }
}

impl SettingsSnapshot {
    /// Returns the monotonic accepted Settings revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Returns durable History policy.
    pub const fn history_retention(&self) -> HistoryRetention {
        self.history_retention
    }
    /// Returns the validated manual/automatic lease duration selection.
    pub const fn clipboard_lease(&self) -> ClipboardLeaseSeconds {
        self.clipboard_lease
    }
    /// Returns the explicit Auto-copy consent state.
    pub const fn auto_copy_consent(&self) -> AutoCopyConsent {
        self.auto_copy_consent
    }
    /// Returns whether the global Auto-copy preference is enabled.
    pub const fn auto_copy_enabled(&self) -> bool {
        self.auto_copy_enabled
    }
    /// Returns whether notifications are enabled.
    pub const fn notifications_enabled(&self) -> bool {
        self.notifications_enabled
    }
    /// Returns the observed notification permission.
    pub const fn notification_permission(&self) -> NotificationPermission {
        self.notification_permission
    }
    /// Returns the persisted Start at Login preference.
    pub const fn start_at_login(&self) -> bool {
        self.start_at_login
    }
    /// Returns a Provider override, where missing inherits global policy.
    pub fn provider_override(&self, provider: &str) -> Option<bool> {
        self.provider_overrides.get(provider).copied()
    }

    /// Computes effective Auto-copy policy for one Provider.
    pub fn auto_copy_allowed_for(&self, provider: &str) -> bool {
        self.auto_copy_consent == AutoCopyConsent::Granted
            && self.auto_copy_enabled
            && self.provider_override(provider).unwrap_or(true)
    }
}

/// Exactly the settings inputs that acceptance must commit atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptancePolicySnapshot {
    revision: u64,
    history_retention: HistoryRetention,
    auto_copy_consent: AutoCopyConsent,
    auto_copy_enabled: bool,
    provider_overrides: BTreeMap<String, bool>,
    notifications_enabled: bool,
}

impl AcceptancePolicySnapshot {
    /// The revision that must be committed before Settings success is exposed.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Computes acceptance-time Auto-copy eligibility.
    pub fn auto_copy_allowed_for(&self, provider: &str) -> bool {
        self.auto_copy_consent == AutoCopyConsent::Granted
            && self.auto_copy_enabled
            && self
                .provider_overrides
                .get(provider)
                .copied()
                .unwrap_or(true)
    }
}

impl From<&SettingsSnapshot> for AcceptancePolicySnapshot {
    fn from(value: &SettingsSnapshot) -> Self {
        Self {
            revision: value.revision,
            history_retention: value.history_retention,
            auto_copy_consent: value.auto_copy_consent,
            auto_copy_enabled: value.auto_copy_enabled,
            provider_overrides: value.provider_overrides.clone(),
            notifications_enabled: value.notifications_enabled,
        }
    }
}

/// One validated Settings request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsChange {
    SetHistoryRetentionDays(u8),
    SetClipboardLeaseSeconds(u8),
    SetAutoCopyEnabled(bool),
    SetProviderAutoCopy { provider: String, enabled: bool },
    GrantAutoCopyConsent,
    RevokeAutoCopyConsent,
}

/// The atomic acceptance-snapshot write boundary owned by Task 20.
pub trait AcceptancePolicyWriter {
    /// Atomically persists the complete Settings snapshot and installs its
    /// acceptance projection. Failure means Settings must remain unchanged.
    fn write_settings_and_acceptance(
        &mut self,
        expected_previous_revision: u64,
        settings: &SettingsSnapshot,
        next: &AcceptancePolicySnapshot,
    ) -> Result<(), SettingsWriteError>;
}

/// A durable acceptance-snapshot write failed or observed a stale revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsWriteError {
    Failed,
    RevisionConflict,
}

/// A Settings request was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsError {
    InvalidHistoryRetention,
    InvalidLeaseSeconds,
    EmptyProvider,
    ConsentRequired,
    InvalidNotificationConfiguration,
    RevisionExhausted,
    PersistenceFailed,
    RevisionConflict,
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHistoryRetention => "History retention must be Off, 1, 7, or 30 days",
            Self::InvalidLeaseSeconds => "Clipboard lease must be 15, 30, or 60 seconds",
            Self::EmptyProvider => "Provider cannot be empty",
            Self::ConsentRequired => "Explicit Auto-copy consent is required",
            Self::InvalidNotificationConfiguration => {
                "Notifications cannot be enabled without operating-system permission"
            }
            Self::RevisionExhausted => "Settings revision cannot be incremented",
            Self::PersistenceFailed => "Settings could not be saved",
            Self::RevisionConflict => "Settings changed elsewhere; refresh and retry",
        })
    }
}
impl std::error::Error for SettingsError {}

/// Settings state machine which updates acceptance policy before success.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    snapshot: SettingsSnapshot,
}

impl Settings {
    /// Starts from v2 defaults.
    pub fn new() -> Self {
        Self::default()
    }
    /// Migrates an old Auto-copy toggle without treating it as consent.
    pub fn from_legacy(legacy: LegacyAutoCopySettings) -> Self {
        Self {
            snapshot: SettingsSnapshot {
                auto_copy_enabled: legacy.auto_copy_enabled,
                ..SettingsSnapshot::default()
            },
        }
    }
    /// Returns the last durably accepted Settings state.
    pub fn snapshot(&self) -> &SettingsSnapshot {
        &self.snapshot
    }
    /// Validates decoded settings, reconciles revoked-consent residue, and
    /// installs the resulting acceptance projection before exposing it.
    pub fn restore(
        persisted: PersistedSettings,
        writer: &mut impl AcceptancePolicyWriter,
    ) -> Result<Self, SettingsError> {
        let mut snapshot = SettingsSnapshot {
            revision: persisted.revision,
            history_retention: persisted.history_retention,
            clipboard_lease: persisted.clipboard_lease,
            auto_copy_consent: persisted.auto_copy_consent,
            auto_copy_enabled: persisted.auto_copy_enabled,
            provider_overrides: persisted.provider_overrides,
            notifications_enabled: persisted.notifications_enabled,
            notification_permission: persisted.notification_permission,
            start_at_login: persisted.start_at_login,
        };
        if snapshot.notifications_enabled
            && snapshot.notification_permission != NotificationPermission::Granted
        {
            return Err(SettingsError::InvalidNotificationConfiguration);
        }
        let previous_revision = snapshot.revision;
        if snapshot.auto_copy_consent == AutoCopyConsent::Declined {
            let needs_reconciliation =
                snapshot.auto_copy_enabled || !snapshot.provider_overrides.is_empty();
            snapshot.auto_copy_enabled = false;
            snapshot.provider_overrides.clear();
            if needs_reconciliation {
                snapshot.revision = previous_revision
                    .checked_add(1)
                    .ok_or(SettingsError::RevisionExhausted)?;
            }
        }
        let acceptance = AcceptancePolicySnapshot::from(&snapshot);
        writer
            .write_settings_and_acceptance(previous_revision, &snapshot, &acceptance)
            .map_err(map_write_error)?;
        Ok(Self { snapshot })
    }
    /// Applies exactly one change transactionally.
    pub fn apply(
        &mut self,
        change: SettingsChange,
        writer: &mut impl AcceptancePolicyWriter,
    ) -> Result<&SettingsSnapshot, SettingsError> {
        let mut next = self.snapshot.clone();
        apply_change(&mut next, change)?;
        let previous_revision = next.revision;
        next.revision = previous_revision
            .checked_add(1)
            .ok_or(SettingsError::RevisionExhausted)?;
        let acceptance = AcceptancePolicySnapshot::from(&next);
        writer
            .write_settings_and_acceptance(previous_revision, &next, &acceptance)
            .map_err(map_write_error)?;
        self.snapshot = next;
        Ok(&self.snapshot)
    }
}

fn map_write_error(error: SettingsWriteError) -> SettingsError {
    match error {
        SettingsWriteError::Failed => SettingsError::PersistenceFailed,
        SettingsWriteError::RevisionConflict => SettingsError::RevisionConflict,
    }
}

fn apply_change(
    snapshot: &mut SettingsSnapshot,
    change: SettingsChange,
) -> Result<(), SettingsError> {
    match change {
        SettingsChange::SetHistoryRetentionDays(days) => {
            snapshot.history_retention = HistoryRetention::try_from(days)
                .map_err(|_| SettingsError::InvalidHistoryRetention)?;
        }
        SettingsChange::SetClipboardLeaseSeconds(seconds) => {
            snapshot.clipboard_lease = ClipboardLeaseSeconds::try_from(seconds)?;
        }
        SettingsChange::SetAutoCopyEnabled(enabled) => snapshot.auto_copy_enabled = enabled,
        SettingsChange::SetProviderAutoCopy { provider, enabled } => {
            if provider.trim().is_empty() {
                return Err(SettingsError::EmptyProvider);
            }
            if snapshot.auto_copy_consent != AutoCopyConsent::Granted && enabled {
                return Err(SettingsError::ConsentRequired);
            }
            snapshot.provider_overrides.insert(provider, enabled);
        }
        SettingsChange::GrantAutoCopyConsent => {
            snapshot.auto_copy_consent = AutoCopyConsent::Granted
        }
        SettingsChange::RevokeAutoCopyConsent => {
            snapshot.auto_copy_consent = AutoCopyConsent::Declined;
            snapshot.auto_copy_enabled = false;
            snapshot.provider_overrides.clear();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeWriter {
        writes: Vec<(u64, SettingsSnapshot, AcceptancePolicySnapshot)>,
        result: Result<(), SettingsWriteError>,
    }
    impl Default for FakeWriter {
        fn default() -> Self {
            Self {
                writes: Vec::new(),
                result: Ok(()),
            }
        }
    }
    impl AcceptancePolicyWriter for FakeWriter {
        fn write_settings_and_acceptance(
            &mut self,
            expected_previous_revision: u64,
            settings: &SettingsSnapshot,
            next: &AcceptancePolicySnapshot,
        ) -> Result<(), SettingsWriteError> {
            self.writes
                .push((expected_previous_revision, settings.clone(), next.clone()));
            self.result
        }
    }

    #[test]
    fn defaults_are_conservative_and_complete() {
        let settings = Settings::new();
        let snapshot = settings.snapshot();
        assert_eq!(snapshot.revision(), 0);
        assert_eq!(snapshot.history_retention(), HistoryRetention::SevenDays);
        assert_eq!(snapshot.clipboard_lease(), ClipboardLeaseSeconds::Thirty);
        assert_eq!(snapshot.auto_copy_consent(), AutoCopyConsent::Unknown);
        assert!(!snapshot.auto_copy_enabled());
        assert!(!snapshot.notifications_enabled());
        assert_eq!(
            snapshot.notification_permission(),
            NotificationPermission::Unknown
        );
        assert!(!snapshot.start_at_login());
        assert!(!snapshot.auto_copy_allowed_for("provider"));
    }

    #[test]
    fn legacy_enabled_auto_copy_is_not_consent() {
        let settings = Settings::from_legacy(LegacyAutoCopySettings {
            auto_copy_enabled: true,
        });
        assert!(settings.snapshot().auto_copy_enabled());
        assert_eq!(
            settings.snapshot().auto_copy_consent(),
            AutoCopyConsent::Unknown
        );
        assert!(!settings.snapshot().auto_copy_allowed_for("provider"));
    }

    #[test]
    fn only_approved_history_and_lease_values_are_accepted() {
        let mut settings = Settings::new();
        let mut writer = FakeWriter::default();
        for days in [0, 1, 7, 30] {
            settings
                .apply(SettingsChange::SetHistoryRetentionDays(days), &mut writer)
                .expect("approved retention");
        }
        for seconds in [15, 30, 60] {
            settings
                .apply(
                    SettingsChange::SetClipboardLeaseSeconds(seconds),
                    &mut writer,
                )
                .expect("approved lease");
        }
        let revision = settings.snapshot().revision();
        assert_eq!(
            settings.apply(SettingsChange::SetHistoryRetentionDays(2), &mut writer),
            Err(SettingsError::InvalidHistoryRetention)
        );
        assert_eq!(
            settings.apply(SettingsChange::SetClipboardLeaseSeconds(45), &mut writer),
            Err(SettingsError::InvalidLeaseSeconds)
        );
        assert_eq!(settings.snapshot().revision(), revision);
        assert_eq!(writer.writes.len(), 7);
    }

    #[test]
    fn acceptance_policy_is_durably_updated_before_settings_success_and_revisions_increment() {
        let mut settings = Settings::new();
        let mut writer = FakeWriter::default();
        let result = settings
            .apply(SettingsChange::GrantAutoCopyConsent, &mut writer)
            .expect("successful update");
        assert_eq!(result.revision(), 1);
        assert_eq!(writer.writes.len(), 1);
        assert_eq!(writer.writes[0].0, 0);
        assert_eq!(writer.writes[0].1.revision(), 1);
        assert_eq!(
            writer.writes[0].1.clipboard_lease(),
            ClipboardLeaseSeconds::Thirty
        );
        assert!(!writer.writes[0].2.auto_copy_allowed_for("provider"));
        settings
            .apply(SettingsChange::SetAutoCopyEnabled(true), &mut writer)
            .expect("successful update");
        assert_eq!(settings.snapshot().revision(), 2);
        assert!(writer.writes[1].2.auto_copy_allowed_for("provider"));
    }

    #[test]
    fn write_failure_or_conflict_never_reports_or_retains_false_success() {
        let mut settings = Settings::new();
        let before = settings.snapshot().clone();
        let mut failed = FakeWriter {
            result: Err(SettingsWriteError::Failed),
            ..FakeWriter::default()
        };
        assert_eq!(
            settings.apply(SettingsChange::GrantAutoCopyConsent, &mut failed),
            Err(SettingsError::PersistenceFailed)
        );
        assert_eq!(settings.snapshot(), &before);
        let mut conflict = FakeWriter {
            result: Err(SettingsWriteError::RevisionConflict),
            ..FakeWriter::default()
        };
        assert_eq!(
            settings.apply(SettingsChange::GrantAutoCopyConsent, &mut conflict),
            Err(SettingsError::RevisionConflict)
        );
        assert_eq!(settings.snapshot(), &before);
    }

    #[test]
    fn consent_revocation_disables_global_policy_and_removes_provider_overrides() {
        let mut settings = Settings::new();
        let mut writer = FakeWriter::default();
        settings
            .apply(SettingsChange::GrantAutoCopyConsent, &mut writer)
            .unwrap();
        settings
            .apply(SettingsChange::SetAutoCopyEnabled(true), &mut writer)
            .unwrap();
        settings
            .apply(
                SettingsChange::SetProviderAutoCopy {
                    provider: "bank".into(),
                    enabled: true,
                },
                &mut writer,
            )
            .unwrap();
        assert!(settings.snapshot().auto_copy_allowed_for("bank"));
        settings
            .apply(SettingsChange::RevokeAutoCopyConsent, &mut writer)
            .unwrap();
        assert_eq!(
            settings.snapshot().auto_copy_consent(),
            AutoCopyConsent::Declined
        );
        assert!(!settings.snapshot().auto_copy_enabled());
        assert_eq!(settings.snapshot().provider_override("bank"), None);
        assert!(!settings.snapshot().auto_copy_allowed_for("bank"));
    }

    #[test]
    fn provider_cannot_enable_automatic_copy_without_consent() {
        let mut settings = Settings::new();
        let mut writer = FakeWriter::default();
        assert_eq!(
            settings.apply(
                SettingsChange::SetProviderAutoCopy {
                    provider: "bank".into(),
                    enabled: true,
                },
                &mut writer,
            ),
            Err(SettingsError::ConsentRequired)
        );
        assert_eq!(settings.snapshot().provider_override("bank"), None);
        assert!(!settings.snapshot().auto_copy_allowed_for("bank"));
        assert_eq!(settings.snapshot().revision(), 0);
        assert!(writer.writes.is_empty());
        assert_eq!(
            settings.apply(
                SettingsChange::SetProviderAutoCopy {
                    provider: "  ".into(),
                    enabled: false
                },
                &mut writer
            ),
            Err(SettingsError::EmptyProvider)
        );
    }

    #[test]
    fn restore_rejects_invalid_notification_state_before_any_write() {
        let mut persisted = PersistedSettings::from(&SettingsSnapshot::default());
        persisted.notifications_enabled = true;
        persisted.notification_permission = NotificationPermission::Denied;
        let mut writer = FakeWriter::default();

        assert!(matches!(
            Settings::restore(persisted, &mut writer),
            Err(SettingsError::InvalidNotificationConfiguration)
        ));
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn restore_reconciles_revoked_consent_residue_in_a_full_atomic_write() {
        let mut persisted = PersistedSettings::from(&SettingsSnapshot::default());
        persisted.revision = 4;
        persisted.auto_copy_consent = AutoCopyConsent::Declined;
        persisted.auto_copy_enabled = true;
        persisted.provider_overrides.insert("bank".into(), true);
        let mut writer = FakeWriter::default();

        let settings = Settings::restore(persisted, &mut writer).expect("reconciled restore");
        assert_eq!(settings.snapshot().revision(), 5);
        assert!(!settings.snapshot().auto_copy_enabled());
        assert_eq!(settings.snapshot().provider_override("bank"), None);
        assert_eq!(writer.writes[0].0, 4);
        assert_eq!(writer.writes[0].1.revision(), 5);
        assert!(!writer.writes[0].2.auto_copy_allowed_for("bank"));
    }

    #[test]
    fn restore_reports_revision_conflict_without_exposing_uninstalled_policy() {
        let persisted = PersistedSettings::from(&SettingsSnapshot::default());
        let mut writer = FakeWriter {
            result: Err(SettingsWriteError::RevisionConflict),
            ..FakeWriter::default()
        };

        assert!(matches!(
            Settings::restore(persisted, &mut writer),
            Err(SettingsError::RevisionConflict)
        ));
        assert_eq!(writer.writes.len(), 1);
    }
}
