# Retain a small encrypted local History

OTPBar stores History only on the user's Mac in encrypted durable storage, with a 7-day default, a hard maximum of 50 Recent Codes, and user choices of Off, 1 day, 7 days, or 30 days. On upgrade, legacy plaintext History is migrated into the encrypted store and then deleted; OTPBar never syncs History to a cloud service. This balances missing-code recovery with the sensitivity of one-time passcodes and makes retention an explicit, enforceable product policy.
