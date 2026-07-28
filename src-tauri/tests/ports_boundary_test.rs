use std::collections::HashMap;

use otpbar::domain::error::ErrorEnvelope;
use otpbar::ports::{Clipboard, ClipboardClearOutcome, RandomSource, SecretStore};

#[derive(Default)]
struct FakePorts {
    clipboard: Option<String>,
    secrets: HashMap<String, Vec<u8>>,
    next_random: u8,
}

impl RandomSource for FakePorts {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ErrorEnvelope> {
        destination.fill(self.next_random);
        self.next_random = self.next_random.wrapping_add(1);
        Ok(())
    }
}

impl SecretStore for FakePorts {
    fn read_secret(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
        Ok(self.secrets.get(key).cloned())
    }

    fn write_secret(&mut self, key: &str, value: &[u8]) -> Result<(), ErrorEnvelope> {
        self.secrets.insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete_secret(&mut self, key: &str) -> Result<(), ErrorEnvelope> {
        self.secrets.remove(key);
        Ok(())
    }
}

impl Clipboard for FakePorts {
    fn read_text(&self) -> Result<Option<String>, ErrorEnvelope> {
        Ok(self.clipboard.clone())
    }

    fn write_text(&mut self, value: &str) -> Result<(), ErrorEnvelope> {
        self.clipboard = Some(value.to_owned());
        Ok(())
    }

    fn clear_if_text(&mut self, expected: &str) -> Result<ClipboardClearOutcome, ErrorEnvelope> {
        if self.clipboard.as_deref() == Some(expected) {
            self.clipboard = None;
            Ok(ClipboardClearOutcome::Cleared)
        } else {
            Ok(ClipboardClearOutcome::Changed)
        }
    }
}

#[test]
fn side_effect_dependencies_can_be_replaced_by_deterministic_ports() {
    let mut ports = FakePorts::default();
    let mut key = [0_u8; 32];

    ports
        .fill_bytes(&mut key)
        .expect("fake entropy should work");
    ports
        .write_secret("state-key", &key)
        .expect("fake secret write should work");
    ports
        .write_text("clipboard-canary")
        .expect("fake clipboard write should work");

    assert_eq!(
        ports
            .read_secret("state-key")
            .expect("fake secret read should work"),
        Some(vec![0; 32])
    );
    assert_eq!(
        ports.read_text().expect("fake clipboard read should work"),
        Some("clipboard-canary".to_owned())
    );
    assert_eq!(
        ports
            .clear_if_text("different")
            .expect("mismatch should be observable"),
        ClipboardClearOutcome::Changed
    );
    assert_eq!(
        ports
            .clear_if_text("clipboard-canary")
            .expect("matching clear should work"),
        ClipboardClearOutcome::Cleared
    );
    assert_eq!(
        ports.read_text().expect("cleared clipboard should read"),
        None
    );
}
