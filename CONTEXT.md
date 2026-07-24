# OTPBar

OTPBar is a macOS menubar product that observes a user's mailbox for one-time passcodes and makes trustworthy, short-lived access to those codes convenient.

## Language

**Authorization**:
The user's revocable grant for OTPBar to observe a Mailbox.
_Avoid_: Login, authentication, account

**Mailbox**:
The authorized collection of Messages that OTPBar observes for one-time passcodes.
_Avoid_: Inbox, email account

**Mailbox Identity**:
The user-recognizable identity of the Mailbox covered by an Authorization.
_Avoid_: Account, email address, user

**Message**:
A single item received from a Mailbox and evaluated for a one-time passcode.
_Avoid_: Email, mail

**Detected OTP**:
A one-time passcode and its supporting message context that OTPBar has accepted with sufficient confidence.
_Avoid_: OTP, match, extracted code

**Provider**:
The service whose access flow a Detected OTP is intended to complete, inferred from the Message rather than the Mailbox vendor.
_Avoid_: Sender, Gmail, issuer

**Seen Message**:
A Message whose identity has already been considered by OTPBar, whether or not it produced a Detected OTP.
_Avoid_: Read message, processed email, duplicate

**Recent Code**:
A Detected OTP presented for immediate reuse in the Desktop Session, whether or not the user retains it in History.
_Avoid_: Entry, item, result

**History**:
The user's durable collection of Detected OTPs, governed by an explicit retention choice and capacity.
_Avoid_: Cache, log, archive

**Auto-copy**:
The user-consented policy that may place a newly Detected OTP on the clipboard without a manual copy action.
_Avoid_: Automatic mode, smart copy

**Clipboard Lease**:
OTPBar's temporary, replaceable claim over clipboard content that it placed there and may clear only while the claim remains valid.
_Avoid_: Clipboard timer, copy timeout

**Monitoring Health**:
The user's current confidence that OTPBar can observe the Mailbox, expressed as healthy, checking, stale, rate-limited, offline, partially degraded, stopped, or unavailable.
_Avoid_: Polling status, connection status, sync status

**Desktop Session**:
The coherent user-visible state of Authorization, Monitoring Health, Recent Codes, settings, privacy, and Clipboard Lease ownership at one moment.
_Avoid_: App state, frontend state, global state

**Disconnect**:
The user's act of ending Authorization while leaving other local data unchanged.
_Avoid_: Sign out, log out, remove account
