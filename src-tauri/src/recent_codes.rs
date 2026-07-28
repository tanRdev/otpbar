//! In-memory Recent Code projection.
//!
//! Recent Codes intentionally do not serialize or access the state store.
//! They are rebuilt from durable History only while retention is enabled.
//! Production command/capability wiring remains intentionally open until
//! Task 20 provides the atomic acceptance and encrypted snapshot owner.

use std::{collections::HashSet, fmt, time::Duration};

use crate::{
    clock::Timestamp,
    state_store::history::{History, HistoryEntry, HistoryEntryId, HistoryRetention},
};

/// Maximum number of Recent Codes visible in one Desktop Session.
pub const RECENT_CODES_CAPACITY: usize = 10;
const SESSION_ONLY_LIFETIME: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecentCodeBacking {
    RestoredHistory,
    CurrentArrival { expires_at: Timestamp },
}

/// One visible Recent Code. It is an in-memory view of a History record or a
/// current-session arrival; it is never a second durable record.
#[derive(Clone, PartialEq, Eq)]
pub struct RecentCode {
    entry: HistoryEntry,
    presented_at: Timestamp,
    backing: RecentCodeBacking,
}

impl fmt::Debug for RecentCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecentCode")
            .field("entry", &self.entry)
            .field("presented_at", &self.presented_at)
            .field("backing", &self.backing)
            .finish()
    }
}

impl RecentCode {
    /// Returns the visible Detected OTP and its supporting context.
    pub fn entry(&self) -> &HistoryEntry {
        &self.entry
    }

    /// Returns when this code entered the Desktop Session projection.
    pub const fn presented_at(&self) -> Timestamp {
        self.presented_at
    }
}

/// A session-only expiry timestamp could not be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecentCodesError {
    UnrepresentableExpiry,
}

/// Bounded in-memory Desktop Session projection of Recent Codes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RecentCodes {
    entries: Vec<RecentCode>,
}

impl fmt::Debug for RecentCodes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecentCodes")
            .field("entries", &self.entries)
            .finish()
    }
}

impl RecentCodes {
    /// Rebuilds the projection for a process restart.
    ///
    /// History Off deliberately restores nothing. Enabled retention uses the
    /// History owner's normalized records and has no independent persistence.
    pub fn restore_from_history(history: &History, now: Timestamp) -> Self {
        if history.retention() == HistoryRetention::Off {
            return Self::default();
        }

        let mut normalized = history.clone();
        normalized.prune_expired(now);
        let entries = normalized
            .entries()
            .iter()
            .take(RECENT_CODES_CAPACITY)
            .cloned()
            .map(|entry| RecentCode {
                presented_at: entry.received_at(),
                entry,
                backing: RecentCodeBacking::RestoredHistory,
            })
            .collect();
        Self { entries }
    }

    /// Returns visible codes, newest first.
    pub fn entries(&self) -> &[RecentCode] {
        &self.entries
    }

    /// Merges a newly accepted Detected OTP into the current Desktop Session.
    ///
    /// Current-session arrivals are retained for 15 minutes when History is
    /// Off. While History is enabled they remain visible as current arrivals;
    /// on a later switch to Off that same 15-minute bound preserves only the
    /// still-current arrivals, never restored historical entries.
    pub fn accept_arrival(
        &mut self,
        entry: HistoryEntry,
        now: Timestamp,
    ) -> Result<(), RecentCodesError> {
        let expires_at = now
            .checked_add(SESSION_ONLY_LIFETIME)
            .ok_or(RecentCodesError::UnrepresentableExpiry)?;
        self.entries
            .retain(|recent| recent.entry.source_message_digest() != entry.source_message_digest());
        self.entries.push(RecentCode {
            entry,
            presented_at: now,
            backing: RecentCodeBacking::CurrentArrival { expires_at },
        });
        self.normalize();
        Ok(())
    }

    /// Applies the retention policy after a setting transition or clock tick.
    ///
    /// When retention is Off, only current-process arrivals survive and only
    /// through their 15-minute session lifetime. When it is enabled, matching
    /// arrivals become History-backed while unmatched arrivals keep their
    /// remaining session lifetime.
    pub fn reconcile_history(&mut self, history: &History, now: Timestamp) {
        if history.retention() == HistoryRetention::Off {
            self.entries.retain(|recent| {
                matches!(recent.backing, RecentCodeBacking::CurrentArrival { expires_at } if now < expires_at)
            });
            self.normalize();
            return;
        }

        let mut normalized = history.clone();
        normalized.prune_expired(now);
        self.entries.retain_mut(|recent| {
            let history_match = normalized
                .entries()
                .iter()
                .any(|entry| entry.source_message_digest() == recent.entry.source_message_digest());
            if history_match {
                recent.backing = RecentCodeBacking::RestoredHistory;
                return true;
            }
            matches!(
                recent.backing,
                RecentCodeBacking::CurrentArrival { expires_at } if now < expires_at
            )
        });
        self.normalize();
    }

    /// Removes a Recent Code after its matching durable History entry is deleted.
    pub fn on_history_entry_deleted(&mut self, id: &HistoryEntryId) {
        self.entries.retain(|recent| recent.entry.id() != id);
    }

    /// Removes the entire projection after a successful History clear.
    pub fn on_history_cleared(&mut self) {
        self.entries.clear();
    }

    fn normalize(&mut self) {
        self.entries.sort_by(|left, right| {
            right
                .presented_at
                .cmp(&left.presented_at)
                .then_with(|| left.entry.id().as_str().cmp(right.entry.id().as_str()))
        });
        let mut seen_sources = HashSet::new();
        self.entries
            .retain(|recent| seen_sources.insert(recent.entry.source_message_digest().clone()));
        self.entries.truncate(RECENT_CODES_CAPACITY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::Timestamp,
        state_store::history::{
            History, HistoryEntry, HistoryEntryId, HistoryProvider, HistoryRetention,
            SourceMessageDigest,
        },
    };

    fn entry(id: &str, source: &str, received_at: i64) -> HistoryEntry {
        let source = format!("{:0<64}", hex::encode(source));
        HistoryEntry::new(
            HistoryEntryId::new(id).expect("opaque history id"),
            "123456",
            "Example message origin",
            HistoryProvider::new("example", "Example").expect("provider"),
            Timestamp::from_unix_millis(received_at),
            SourceMessageDigest::new(source).expect("canonical source identity"),
        )
        .expect("valid entry")
    }

    #[test]
    fn enabled_restart_restores_only_the_newest_ten_unexpired_history_entries() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let history = History::restore(
            HistoryRetention::SevenDays,
            (0..12).map(|index| {
                entry(
                    &format!("history-{index}"),
                    &format!("source-{index}"),
                    now.unix_millis() - index,
                )
            }),
            now,
        );

        let recent = RecentCodes::restore_from_history(&history, now);

        assert_eq!(recent.entries().len(), 10);
        assert_eq!(recent.entries()[0].entry().id().as_str(), "history-0");
        assert_eq!(recent.entries()[9].entry().id().as_str(), "history-9");
    }

    #[test]
    fn history_off_keeps_current_arrivals_for_fifteen_minutes_but_restores_none() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let mut recent = RecentCodes::default();
        recent
            .accept_arrival(entry("arrival", "arrival-source", now.unix_millis()), now)
            .expect("representable 15-minute expiry");
        let off_history = History::restore(HistoryRetention::Off, [], now);

        assert!(RecentCodes::restore_from_history(&off_history, now)
            .entries()
            .is_empty());
        recent.reconcile_history(
            &off_history,
            now.checked_add(Duration::from_secs(15 * 60 - 1))
                .expect("representable fixture"),
        );
        assert_eq!(recent.entries().len(), 1);
        recent.reconcile_history(
            &off_history,
            now.checked_add(Duration::from_secs(15 * 60))
                .expect("representable fixture"),
        );
        assert!(recent.entries().is_empty());
    }

    #[test]
    fn history_clear_and_expiry_remove_their_projected_codes_coherently() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let first = entry("first", "first-source", now.unix_millis());
        let second = entry("second", "second-source", now.unix_millis() - 1);
        let first_id = first.id().clone();
        let mut history = History::restore(HistoryRetention::SevenDays, [first, second], now);
        let mut recent = RecentCodes::restore_from_history(&history, now);

        assert!(history.delete(&first_id));
        recent.on_history_entry_deleted(&first_id);
        assert_eq!(recent.entries().len(), 1);
        history.clear();
        recent.on_history_cleared();
        assert!(recent.entries().is_empty());
    }

    #[test]
    fn restore_deduplicates_source_messages_and_keeps_the_newest_code() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let history = History::restore(
            HistoryRetention::SevenDays,
            [
                entry("older", "same-source", now.unix_millis() - 10),
                entry("newer", "same-source", now.unix_millis()),
            ],
            now,
        );

        let recent = RecentCodes::restore_from_history(&history, now);

        assert_eq!(recent.entries().len(), 1);
        assert_eq!(recent.entries()[0].entry().id().as_str(), "newer");
    }

    #[test]
    fn history_off_keeps_at_most_ten_current_session_arrivals() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let off_history = History::restore(HistoryRetention::Off, [], now);
        let mut recent = RecentCodes::default();
        for index in 0..12 {
            let presented_at = now
                .checked_add(Duration::from_secs(index))
                .expect("representable fixture");
            recent
                .accept_arrival(
                    entry(
                        &format!("arrival-{index}"),
                        &format!("source-{index}"),
                        presented_at.unix_millis(),
                    ),
                    presented_at,
                )
                .expect("representable expiry");
        }

        recent.reconcile_history(&off_history, now);

        assert_eq!(recent.entries().len(), RECENT_CODES_CAPACITY);
        assert_eq!(recent.entries()[0].entry().id().as_str(), "arrival-11");
        assert_eq!(recent.entries()[9].entry().id().as_str(), "arrival-2");
    }

    #[test]
    fn enabled_history_expiry_removes_current_and_restored_projection_entries() {
        let received_at = Timestamp::from_unix_millis(10 * 24 * 60 * 60 * 1_000);
        let mut history = History::restore(
            HistoryRetention::OneDay,
            [entry("expiring", "source", received_at.unix_millis())],
            received_at,
        );
        let mut recent = RecentCodes::restore_from_history(&history, received_at);
        recent
            .accept_arrival(
                entry("replacement", "source", received_at.unix_millis()),
                received_at,
            )
            .expect("representable expiry");
        let expiry = received_at
            .checked_add(Duration::from_secs(24 * 60 * 60))
            .expect("representable fixture");

        history.prune_expired(expiry);
        recent.reconcile_history(&history, expiry);

        assert!(history.entries().is_empty());
        assert!(recent.entries().is_empty());
    }

    #[test]
    fn recent_code_debug_output_redacts_detected_otp_values() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let mut recent = RecentCodes::default();
        recent
            .accept_arrival(entry("arrival", "source", now.unix_millis()), now)
            .expect("representable expiry");

        assert!(!format!("{recent:?}").contains("123456"));
        assert!(format!("{recent:?}").contains("[redacted]"));
    }

    #[test]
    fn off_arrival_survives_enabling_history_without_a_match_until_session_expiry() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let mut recent = RecentCodes::default();
        recent
            .accept_arrival(entry("arrival", "source", now.unix_millis()), now)
            .expect("representable expiry");
        let enabled_history = History::restore(HistoryRetention::SevenDays, [], now);

        recent.reconcile_history(
            &enabled_history,
            now.checked_add(Duration::from_secs(5 * 60))
                .expect("representable fixture"),
        );
        assert_eq!(recent.entries().len(), 1);

        recent.reconcile_history(
            &enabled_history,
            now.checked_add(Duration::from_secs(15 * 60))
                .expect("representable fixture"),
        );
        assert!(recent.entries().is_empty());
    }

    #[test]
    fn off_arrival_with_a_history_match_transitions_to_history_backing() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let arrival = entry("arrival", "source", now.unix_millis());
        let mut recent = RecentCodes::default();
        recent
            .accept_arrival(arrival.clone(), now)
            .expect("representable expiry");
        let enabled_history = History::restore(HistoryRetention::SevenDays, [arrival], now);

        recent.reconcile_history(&enabled_history, now);
        let off_history = History::restore(HistoryRetention::Off, [], now);
        recent.reconcile_history(
            &off_history,
            now.checked_add(Duration::from_secs(1))
                .expect("representable fixture"),
        );

        assert!(recent.entries().is_empty());
    }
}
