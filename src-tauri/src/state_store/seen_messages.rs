//! Durable, privacy-preserving Seen Message idempotency ledger.
//!
//! The ledger is deliberately independent of History and of the Desktop
//! Session.  An acceptance owner commits it in the same encrypted snapshot as
//! the acceptance decision, but this pure module owns no storage or effects.

use std::{collections::HashSet, fmt, time::Duration};

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use crate::clock::Timestamp;

use super::{crypto::keyed_digest, StateKey};

/// The maximum age of a Seen Message decision.
pub const SEEN_MESSAGE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// The hard upper bound for durable Seen Message decisions.
pub const SEEN_MESSAGE_CAPACITY: usize = 10_000;

/// A keyed HMAC identity over one Mailbox Identity and one Message identity.
///
/// This is intentionally opaque: raw Mailbox Identity, Message ID, subject,
/// and content never enter the durable ledger.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SeenMessageIdentity(String);

impl SeenMessageIdentity {
    /// Derives the opaque identity from the Mailbox Identity and Message
    /// identity using the validated 256-bit snapshot key. Inputs are only
    /// present during this calculation and are not retained by the result.
    pub fn derive(key: &StateKey, mailbox_identity: &str, message_identity: &str) -> Self {
        // Length-prefixing makes the pair unambiguous: ("ab", "c") cannot
        // collide with ("a", "bc") before cryptographic protection.
        let capacity = 16usize
            .checked_add(mailbox_identity.len())
            .and_then(|length| length.checked_add(message_identity.len()))
            .expect("process strings fit in a Vec");
        let mut material = Zeroizing::new(Vec::with_capacity(capacity));
        material.extend_from_slice(&(mailbox_identity.len() as u64).to_be_bytes());
        material.extend_from_slice(mailbox_identity.as_bytes());
        material.extend_from_slice(&(message_identity.len() as u64).to_be_bytes());
        material.extend_from_slice(message_identity.as_bytes());
        Self(hex::encode(keyed_digest(
            key,
            b"otpbar-seen-message-identity-v1",
            material.as_slice(),
        )))
    }

    /// Validates the canonical lowercase hexadecimal HMAC-SHA-256 shape.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidSeenMessage> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InvalidSeenMessage::InvalidIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the opaque identity for authenticated snapshot serialization.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SeenMessageIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SeenMessageIdentity([redacted])")
    }
}

impl<'de> Deserialize<'de> for SeenMessageIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The terminal result of considering a Message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeenMessageDecision {
    /// The Message produced an accepted Detected OTP.
    Detected,
    /// The Message was considered but did not produce an accepted OTP.
    Rejected,
}

/// A validated, payload-free durable Seen Message decision.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenMessage {
    identity: SeenMessageIdentity,
    decision: SeenMessageDecision,
    decided_at: Timestamp,
}

impl SeenMessage {
    /// Creates one payload-free terminal decision.
    pub const fn new(
        identity: SeenMessageIdentity,
        decision: SeenMessageDecision,
        decided_at: Timestamp,
    ) -> Self {
        Self {
            identity,
            decision,
            decided_at,
        }
    }

    /// Returns the opaque keyed Message identity.
    pub fn identity(&self) -> &SeenMessageIdentity {
        &self.identity
    }

    /// Returns the terminal acceptance decision.
    pub const fn decision(&self) -> SeenMessageDecision {
        self.decision
    }

    /// Returns when the terminal decision was made.
    pub const fn decided_at(&self) -> Timestamp {
        self.decided_at
    }
}

impl fmt::Debug for SeenMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeenMessage")
            .field("identity", &self.identity)
            .field("decision", &self.decision)
            .field("decided_at", &self.decided_at)
            .finish()
    }
}

/// A structurally invalid durable Seen Message record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidSeenMessage {
    /// The persisted identity was not a canonical keyed digest.
    InvalidIdentity,
}

impl fmt::Display for InvalidSeenMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Seen Message identity must be 64 lowercase hexadecimal characters")
    }
}

impl std::error::Error for InvalidSeenMessage {}

/// Pure retention and deduplication policy for Seen Message decisions.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct SeenMessageLedger {
    entries: Vec<SeenMessage>,
}

impl fmt::Debug for SeenMessageLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeenMessageLedger")
            .field("entries", &self.entries)
            .finish()
    }
}

impl SeenMessageLedger {
    /// Restores durable decisions, pruning expired records and the oldest
    /// excess after resolving duplicate identities newest-first.
    pub fn restore(entries: impl IntoIterator<Item = SeenMessage>, now: Timestamp) -> Self {
        let mut ledger = Self {
            entries: entries.into_iter().collect(),
        };
        ledger.normalize(now);
        ledger
    }

    /// Returns newest-first payload-free decisions.
    pub fn entries(&self) -> &[SeenMessage] {
        &self.entries
    }

    /// Returns the existing terminal decision for an unexpired Message.
    pub fn decision_for(
        &mut self,
        identity: &SeenMessageIdentity,
        now: Timestamp,
    ) -> Option<SeenMessageDecision> {
        self.normalize(now);
        self.entries
            .iter()
            .find(|entry| entry.identity == *identity)
            .map(SeenMessage::decision)
    }

    /// Records one terminal decision unless the Message has already been seen.
    ///
    /// The acceptance owner uses `false` to avoid publishing duplicate effects.
    pub fn record(
        &mut self,
        identity: SeenMessageIdentity,
        decision: SeenMessageDecision,
        now: Timestamp,
    ) -> bool {
        self.normalize(now);
        if self.entries.iter().any(|entry| entry.identity == identity) {
            return false;
        }
        let inserted_identity = identity.clone();
        self.entries.push(SeenMessage::new(identity, decision, now));
        self.normalize(now);
        self.entries
            .iter()
            .any(|entry| entry.identity == inserted_identity)
    }

    /// Removes decisions outside the fixed 30-day retention window.
    pub fn prune(&mut self, now: Timestamp) {
        self.normalize(now);
    }

    fn normalize(&mut self, now: Timestamp) {
        self.entries.retain(|entry| is_unexpired(entry, now));
        self.entries.sort_by(|left, right| {
            right
                .decided_at
                .cmp(&left.decided_at)
                .then_with(|| left.identity.as_str().cmp(right.identity.as_str()))
        });
        let mut identities = HashSet::new();
        self.entries
            .retain(|entry| identities.insert(entry.identity.clone()));
        self.entries.truncate(SEEN_MESSAGE_CAPACITY);
    }
}

fn is_unexpired(entry: &SeenMessage, now: Timestamp) -> bool {
    entry
        .decided_at
        .checked_add(SEEN_MESSAGE_RETENTION)
        .is_none_or(|expires_at| now < expires_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_store::{crypto::key_from_bytes, CryptoError};

    fn identity(seed: &str) -> SeenMessageIdentity {
        SeenMessageIdentity::new(format!("{:0<64}", hex::encode(seed))).expect("canonical HMAC")
    }

    #[test]
    fn accepted_message_remains_seen_after_restart() {
        let now = Timestamp::from_unix_millis(31 * 24 * 60 * 60 * 1_000);
        let message = identity("mailbox-a:message-a");
        let mut first_run = SeenMessageLedger::default();
        assert!(first_run.record(message.clone(), SeenMessageDecision::Detected, now));

        let mut restarted = SeenMessageLedger::restore(first_run.entries().to_vec(), now);
        assert_eq!(
            restarted.decision_for(&message, now),
            Some(SeenMessageDecision::Detected)
        );
        assert!(!restarted.record(message, SeenMessageDecision::Detected, now));
    }

    #[test]
    fn keyed_mailbox_identity_prevents_cross_mailbox_collisions() {
        let now = Timestamp::from_unix_millis(31 * 24 * 60 * 60 * 1_000);
        let key = key_from_bytes(&[7; 32]).expect("valid 256-bit StateKey");
        let mailbox_a_message = SeenMessageIdentity::derive(&key, "mailbox-a", "message-123");
        let mailbox_b_same_message = SeenMessageIdentity::derive(&key, "mailbox-b", "message-123");
        let mut ledger = SeenMessageLedger::default();

        assert_ne!(mailbox_a_message, mailbox_b_same_message);
        assert!(ledger.record(
            mailbox_a_message.clone(),
            SeenMessageDecision::Detected,
            now
        ));
        assert!(ledger.record(
            mailbox_b_same_message.clone(),
            SeenMessageDecision::Detected,
            now
        ));
        assert_eq!(
            ledger.decision_for(&mailbox_a_message, now),
            Some(SeenMessageDecision::Detected)
        );
        assert_eq!(
            ledger.decision_for(&mailbox_b_same_message, now),
            Some(SeenMessageDecision::Detected)
        );
    }

    #[test]
    fn rejected_messages_are_durable_seen_decisions() {
        let now = Timestamp::from_unix_millis(31 * 24 * 60 * 60 * 1_000);
        let message = identity("rejected");
        let mut ledger = SeenMessageLedger::default();
        assert!(ledger.record(message.clone(), SeenMessageDecision::Rejected, now));

        let mut restarted = SeenMessageLedger::restore(ledger.entries().to_vec(), now);
        assert_eq!(
            restarted.decision_for(&message, now),
            Some(SeenMessageDecision::Rejected)
        );
    }

    #[test]
    fn history_operations_do_not_change_the_seen_ledger() {
        let now = Timestamp::from_unix_millis(31 * 24 * 60 * 60 * 1_000);
        let message = identity("history-off-and-clear");
        let mut ledger = SeenMessageLedger::default();
        assert!(ledger.record(message.clone(), SeenMessageDecision::Detected, now));

        // History has no input to this module: an acceptance owner may clear
        // it or set it Off without altering this independently persisted ledger.
        assert_eq!(
            ledger.decision_for(&message, now),
            Some(SeenMessageDecision::Detected)
        );
    }

    #[test]
    fn restore_and_record_prune_exact_30_day_boundary_and_enforce_capacity() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let boundary = now
            .checked_add(SEEN_MESSAGE_RETENTION)
            .map(|timestamp| {
                Timestamp::from_unix_millis(
                    now.unix_millis() - (timestamp.unix_millis() - now.unix_millis()),
                )
            })
            .expect("representable fixture");
        let entries = (0..=SEEN_MESSAGE_CAPACITY)
            .map(|index| {
                SeenMessage::new(
                    identity(&format!("message-{index}")),
                    SeenMessageDecision::Detected,
                    Timestamp::from_unix_millis(now.unix_millis() - index as i64),
                )
            })
            .chain(std::iter::once(SeenMessage::new(
                identity("expired"),
                SeenMessageDecision::Rejected,
                boundary,
            )));

        let ledger = SeenMessageLedger::restore(entries, now);
        assert_eq!(ledger.entries().len(), SEEN_MESSAGE_CAPACITY);
        assert_eq!(ledger.entries()[0].identity(), &identity("message-0"));
        assert_eq!(
            ledger.entries()[SEEN_MESSAGE_CAPACITY - 1].identity(),
            &identity(&format!("message-{}", SEEN_MESSAGE_CAPACITY - 1))
        );
    }

    #[test]
    fn record_reports_failure_when_capacity_would_evict_the_new_acceptance() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let incoming = SeenMessageIdentity::new("f".repeat(64)).expect("canonical identity");
        for decision_time in [now, Timestamp::from_unix_millis(now.unix_millis() + 1)] {
            let entries = (1..=SEEN_MESSAGE_CAPACITY).map(|index| {
                SeenMessage::new(
                    SeenMessageIdentity::new(format!("{index:064x}")).expect("canonical identity"),
                    SeenMessageDecision::Detected,
                    decision_time,
                )
            });
            let mut ledger = SeenMessageLedger::restore(entries, now);

            assert!(
                !ledger.record(incoming.clone(), SeenMessageDecision::Detected, now),
                "an acceptance at {decision_time:?} that cannot retain its Seen identity must not report success"
            );
            assert_eq!(ledger.decision_for(&incoming, now), None);
        }
    }

    #[test]
    fn duplicate_restore_keeps_newest_decision_and_record_does_not_mutate_it() {
        let now = Timestamp::from_unix_millis(31 * 24 * 60 * 60 * 1_000);
        let message = identity("duplicate");
        let mut ledger = SeenMessageLedger::restore(
            [
                SeenMessage::new(
                    message.clone(),
                    SeenMessageDecision::Rejected,
                    Timestamp::from_unix_millis(now.unix_millis() - 1),
                ),
                SeenMessage::new(message.clone(), SeenMessageDecision::Detected, now),
            ],
            now,
        );

        assert_eq!(
            ledger.decision_for(&message, now),
            Some(SeenMessageDecision::Detected)
        );
        assert!(!ledger.record(message.clone(), SeenMessageDecision::Rejected, now));
        assert_eq!(
            ledger.decision_for(&message, now),
            Some(SeenMessageDecision::Detected)
        );
    }

    #[test]
    fn malformed_persisted_identity_is_rejected_and_debug_redacts_it() {
        let canonical = "ab".repeat(32);
        let identity = SeenMessageIdentity::new(canonical.clone()).expect("canonical identity");
        let serialized = serde_json::to_string(&identity).expect("serialize opaque identity");
        assert_eq!(
            serde_json::from_str::<SeenMessageIdentity>(&serialized).expect("validated decode"),
            identity
        );
        assert!(serde_json::from_str::<SeenMessageIdentity>("\"raw-message-id\"").is_err());
        assert!(!format!("{identity:?}").contains(&canonical));
        assert!(format!("{identity:?}").contains("[redacted]"));
    }

    #[test]
    fn persisted_records_are_validated_then_normalized_through_restore() {
        let now = Timestamp::from_unix_millis(40 * 24 * 60 * 60 * 1_000);
        let duplicate = identity("duplicate-from-json");
        let records = vec![
            SeenMessage::new(
                duplicate.clone(),
                SeenMessageDecision::Rejected,
                Timestamp::from_unix_millis(now.unix_millis() - 1),
            ),
            SeenMessage::new(duplicate, SeenMessageDecision::Detected, now),
            SeenMessage::new(
                identity("expired-from-json"),
                SeenMessageDecision::Rejected,
                Timestamp::from_unix_millis(now.unix_millis() - 30 * 24 * 60 * 60 * 1_000),
            ),
        ];
        let encoded = serde_json::to_string(&records).expect("serialize records");
        let decoded: Vec<SeenMessage> = serde_json::from_str(&encoded).expect("validated decode");
        let ledger = SeenMessageLedger::restore(decoded, now);

        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(
            ledger.entries()[0].decision(),
            SeenMessageDecision::Detected
        );
    }

    #[test]
    fn only_an_exact_256_bit_state_key_can_be_constructed_for_identity_derivation() {
        assert!(matches!(
            key_from_bytes(&[0; 31]),
            Err(CryptoError::InvalidStoredKey)
        ));
        assert!(matches!(
            key_from_bytes(&[0; 33]),
            Err(CryptoError::InvalidStoredKey)
        ));
        let key = key_from_bytes(&[0; 32]).expect("exactly 256 bits");
        assert_eq!(
            SeenMessageIdentity::derive(&key, "mailbox", "message")
                .as_str()
                .len(),
            64
        );
    }

    #[test]
    fn clock_rollback_and_expiry_overflow_do_not_drop_seen_messages() {
        let future = SeenMessage::new(
            identity("future"),
            SeenMessageDecision::Detected,
            Timestamp::from_unix_millis(10_000),
        );
        let rollback = SeenMessageLedger::restore([future], Timestamp::from_unix_millis(1));
        assert_eq!(rollback.entries().len(), 1);

        let overflow = SeenMessage::new(
            identity("overflow"),
            SeenMessageDecision::Rejected,
            Timestamp::from_unix_millis(i64::MAX),
        );
        let overflow_ledger =
            SeenMessageLedger::restore([overflow], Timestamp::from_unix_millis(i64::MAX));
        assert_eq!(overflow_ledger.entries().len(), 1);
    }
}
