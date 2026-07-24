<div align="center">

# OTPBar

![platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
[![Build](https://github.com/tanRdev/otpbar/actions/workflows/build.yml/badge.svg)](https://github.com/tanRdev/otpbar/actions)

_A lightweight macOS menubar application that automatically copies OTP codes from your Gmail to your clipboard._

![Screenshot](https://github.com/tanRdev/otpbar/raw/main/screenshots/otpbar.png)

</div>

## Features

- **Real-time monitoring** — Polls Gmail every 8 seconds for new OTP codes
- **Auto-copy** — Detected OTPs are automatically copied to your clipboard
- **Privacy-focused** — OTP codes redacted from logs, message IDs hashed, tokens stored in macOS Keychain
- **Smart notifications** — Desktop notifications when OTP is detected (3-second cooldown)
- **Recent codes** — Quick access to your last 10 OTP codes via menubar dropdown
- **Provider recognition** — Recognizes 80+ service providers (Google, Apple, Microsoft, etc.)

## Quick Start

### Prerequisites

- macOS 10.13 or later
- Rust (latest stable)
- Node.js 18+
- Xcode Command Line Tools

### From Source

```bash
git clone https://github.com/tanRdev/otpbar.git
cd otpbar
npm install
cp .env.example .env
```

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the **Gmail API**
4. Create OAuth 2.0 credentials (Desktop app)
5. Add `http://localhost:8234` as an authorized redirect URI
6. Copy your client ID and secret to `.env`:

```bash
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
```

### Run

```bash
npm run tauri dev
```

The app will appear in your menubar. Click the icon to sign in with Google.

### Build

```bash
npm run tauri build
```

Creates a DMG at `src-tauri/target/release/bundle/dmg/`.

## Usage

1. Click the OTPBar icon in your menubar
2. Sign in with your Google account
3. OTP codes sent to your Gmail will be automatically detected and copied
4. Access recent codes from the dropdown menu
5. Click "Sign Out" to disconnect

## Tech Stack

- **Backend**: Rust + [Tauri 2](https://tauri.app/)
- **Frontend**: React 19 + TypeScript
- **Styling**: Tailwind CSS 4
- **Build**: Vite
- **Storage**: macOS Keychain

## Security

- OAuth tokens stored in macOS Keychain
- OTP codes redacted from logs
- Message IDs hashed before logging
- Read-only Gmail API scope (`gmail.readonly`)
- Local-only processing (no external data transmission)

## Project Structure

```
otpbar/
├── src/                      # React frontend
│   ├── components/           # UI components
│   ├── lib/                  # Utilities and Tauri API wrapper
│   ├── types/                # TypeScript type definitions
│   └── App.tsx              # Main React component
├── src-tauri/               # Rust backend
│   ├── src/
│   │   ├── main.rs          # App entry, tray setup, polling loop
│   │   ├── gmail.rs         # Gmail API client, OAuth flow
│   │   ├── otp.rs           # OTP extraction logic
│   │   ├── keychain.rs      # Keychain storage
│   │   └── oauth_server.rs  # Local OAuth callback server
│   ├── Cargo.toml           # Rust dependencies
│   └── tauri.conf.json      # Tauri configuration
└── package.json             # Node.js dependencies
```

## Troubleshooting

### App doesn't appear in menubar

Make sure the app built successfully. Check `src-tauri/target/release/bundle/dmg/` for the built app.

### OAuth fails with redirect URI error

Ensure you added `http://localhost:8234` as an authorized redirect URI in Google Cloud Console.

### OTP codes not being detected

- Verify Gmail API is enabled in Google Cloud Console
- Check that your account has unread emails containing OTP codes
- Review logs in Console for any errors

## Acknowledgments

Built with [Tauri](https://tauri.app/) · [React](https://react.dev/) · [Gmail API](https://developers.google.com/gmail/api)
