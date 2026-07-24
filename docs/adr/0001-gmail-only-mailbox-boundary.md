# Keep v2 Gmail-only behind a narrow Mailbox boundary

OTPBar v2 supports Gmail only. The modernization will isolate Gmail behind a narrow Mailbox contract so intake and interpretation do not depend on Gmail transport details, but it will not add speculative provider abstractions or another adapter. This keeps security and correctness work focused while avoiding a second rewrite if a validated mailbox integration is added later.
