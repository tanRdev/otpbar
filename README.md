# OTPBar

A minimal macOS menubar application that monitors Gmail for OTP (One-Time Password) codes and automatically copies them to your clipboard.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

Built with [Tauri 2](https://tauri.app/) - a lightweight, secure alternative to Electron.

## Features

- Monitors Gmail for OTP codes in real-time (polls every 8 seconds)
- Auto-copies detected OTP codes to clipboard
- Desktop notifications when OTP is detected
- Stores up to 10 recent OTP codes in memory
- Secure OAuth 2.0 authentication with Google (tokens stored in macOS Keychain)
- Clean, minimal dark-themed menubar interface
- Recognizes 80+ service providers (Google, Apple, Microsoft, etc.)

## Prerequisites

### macOS Development

- **Rust** (latest stable): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js** (v18 or higher): `brew install node` or from [nodejs.org](https://nodejs.org/)
- **Xcode Command Line Tools**: `xcode-select --install`

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/tanRdev/otpbar.git
   cd otpbar
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up Google OAuth credentials (see [Google OAuth Setup](#google-oauth-20-setup))

4. Run the app:
   ```bash
   npm run dev
   ```

### From Releases

Download the latest DMG from the [Releases](https://github.com/tanRdev/otpbar/releases) page.

## Google OAuth 2.0 Setup

To use OTPBar, you need to create Google OAuth 2.0 credentials:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)

2. Create a new project:
   - Click project dropdown at the top
   - Click "New Project"
   - Enter a project name (e.g., "otpbar")
   - Click "Create"

3. Enable Gmail API:
   - Go to "APIs & Services" > "Library"
   - Search for "Gmail API"
   - Click on it and press "Enable"

4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Desktop app" as the application type
   - Name: "otpbar"
   - Click "Create"

5. Copy your credentials:
   - Note down the **Client ID** and **Client Secret** from the popup

6. Create a `.env` file in the project root:
   ```bash
   cp .env.example .env
   ```

7. Edit `.env` and add your credentials:
   ```
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret
   ```

## Usage

1. Run the app:
   ```bash
   npm run dev
   ```

2. Click the OTPBar icon in your menubar

3. Click "Sign in with Google" to authenticate

4. Grant permission to read your Gmail

5. OTPBar will now monitor your Gmail for codes:
   - When an OTP is detected, it's automatically copied to clipboard
   - A notification appears with the OTP code
   - Click the menubar icon to view recent codes

6. Click any code in the list to copy it again

7. Use "Sign Out" to disconnect your account

## Building for Distribution

To create a distributable DMG:

```bash
npm run tauri build
```

The DMG will be created in `src-tauri/target/release/bundle/dmg/`.

## Development

```bash
npm run dev          # Start development server with hot reload
npm run build        # Build frontend only
npm run tauri dev    # Run Tauri in dev mode
```

## Tech Stack

- **Backend**: Rust with Tauri 2.0
- **Frontend**: React 19 + TypeScript
- **Styling**: Tailwind CSS 4
- **Build**: Vite
- **Storage**: macOS Keychain via `keyring` crate

## OTP Detection

OTPBar detects codes using multiple regex patterns:

- 4-8 digit codes
- Common phrases like "your code is", "verification code", "enter to verify"
- Dashed formats (e.g., 123-456)

Codes are extracted from email subject, snippet, and body.

## Troubleshooting

**Authentication fails:**
- Ensure your Google Cloud project has the Gmail API enabled
- Verify your OAuth consent screen is configured
- Check that `.env` file exists with valid credentials

**No OTP codes detected:**
- The app monitors unread emails from the last 24 hours
- Check that emails are unread when received
- Ensure the OTP format matches one of the supported patterns

**Notifications not appearing:**
- Check macOS notification permissions in System Preferences

## Roadmap

Potential features for future releases:
- [ ] Support for multiple email providers
- [ ] Configurable polling interval
- [ ] Notification toggle
- [ ] Persistent code history
- [ ] Settings UI

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License

## Acknowledgments

- Built with [Tauri](https://tauri.app/)
- Uses [React](https://react.dev/)
- Powered by [Google Gmail API](https://developers.google.com/gmail/api)
