# OTPBar

![Build](https://github.com/tanRdev/otpbar/actions/workflows/build.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![platform](https://img.shields.io/badge/platform-macos-lightgrey.svg)

A lightweight macOS menubar application that automatically copies One-Time Password (OTP) codes from your Gmail to your clipboard.

![Screenshot](https://github.com/tanRdev/otpbar/raw/main/screenshots/otpbar.png)

## Features

- **Real-time monitoring**: Polls Gmail every 8 seconds for new OTP codes
- **Auto-copy**: Detected OTPs are automatically copied to your clipboard
- **Privacy-focused**: OTP codes redacted from logs, message IDs hashed, tokens stored in macOS Keychain
- **Smart notifications**: Desktop notifications when OTP is detected (3-second cooldown)
- **Recent codes**: Quick access to your last 10 OTP codes via menubar dropdown
- **Provider recognition**: Recognizes 80+ service providers (Google, Apple, Microsoft, etc.)

## Quick Start

### From Source

```bash
git clone https://github.com/tanRdev/otpbar.git
cd otpbar
npm install
npm run dev
```

### From Releases

Download the latest DMG from the [Releases](https://github.com/tanRdev/otpbar/releases) page.

## Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the Gmail API
4. Create OAuth 2.0 credentials (Desktop app)
5. Set environment variables:
   ```bash
   export GOOGLE_CLIENT_ID=your-client-id
   export GOOGLE_CLIENT_SECRET=your-client-secret
   ```

## Development

```bash
npm run dev          # Start development server
npm run build        # Build frontend
npm run tauri build  # Create distributable
```

## Building

```bash
npm run tauri build
```

Creates `src-tauri/target/release/bundle/dmg/`.

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
- Read-only Gmail API scope
- Local-only processing (no external data transmission)

## License

MIT

## Acknowledgments

Built with [Tauri](https://tauri.app/) · [React](https://react.dev/) · [Gmail API](https://developers.google.com/gmail/api)
