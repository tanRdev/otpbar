# otpbar

A minimal Electron menubar app that monitors Gmail for OTP (One-Time Password) codes and automatically copies them to your clipboard.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

## Features

- 🎯 Monitors Gmail for OTP codes in real-time
- 📋 Auto-copies detected OTP codes to clipboard
- 🔔 Desktop notifications when OTP is detected
- 💾 Stores up to 10 recent OTP codes
- 🔒 Secure OAuth 2.0 authentication with Google
- 🖥️ Clean, minimal menubar interface

## Prerequisites

- Node.js (v16 or higher)
- npm (comes with Node.js)

## Installation

### Homebrew (Recommended for macOS)

```bash
brew install --cask otpbar
```

### From Source

1. Clone repository:
   ```bash
   git clone https://github.com/tanRdev/otpbar.git
   cd otpbar
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up Google OAuth credentials (see [Google OAuth Setup](#google-oauth-20-setup))

4. Run app:
   ```bash
   npm start
   ```

### From Releases

Download the latest release for your platform from the [Releases](https://github.com/tanRdev/otpbar/releases) page and follow installation instructions for your OS.

### Quick Install (macOS)

```bash
curl -sSL https://raw.githubusercontent.com/tanRdev/otpbar/main/install.sh | bash
```

## Google OAuth 2.0 Setup

To use otpbar, you need to create Google OAuth 2.0 credentials:

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
   npm start
   ```

2. Click the otpbar icon in your menubar

3. Click "Sign in with Google" to authenticate

4. Grant permission to read your Gmail

5. otpbar will now monitor your Gmail for codes:
   - When an OTP is detected, it's automatically copied to clipboard
   - A notification appears with the OTP code
   - Click the menubar icon to view recent codes

6. Click any code in the list to copy it again

7. Use "Sign Out" to disconnect your account

## Building from Source

To build the app for distribution:

1. Install dependencies:
   ```bash
   npm install
   ```

2. Build TypeScript:
   ```bash
   npm run build
   ```

3. Create distribution packages:
   ```bash
   npm run dist
   ```

This will create DMG files in the `dist/` directory for both Apple Silicon (arm64) and Intel (x64) Macs.

## Development

For development with auto-rebuild:

```bash
npm run dev
```

## Icons

The app icon was generated programmatically. To regenerate:

```bash
node scripts/create-icons.js app    # Generate app icon (ICNS + PNG)
node scripts/create-icons.js tray  # Generate tray icon (PNG)
```

## Security Notes

- OAuth tokens are stored securely using the system keychain (via `keytar`)
- Only read access to Gmail is requested
- No personal data is collected or transmitted to third parties
- Credentials are stored locally in `.env` (add to `.gitignore`)

## Troubleshooting

**Authentication fails:**
- Ensure your Google Cloud project has the Gmail API enabled
- Verify your OAuth consent screen is configured
- Check that the redirect URI matches the app's configuration (http://localhost:[dynamic port]/callback)

**No OTP codes detected:**
- Verify your Gmail inbox is being monitored
- Check that emails are unread when received
- Ensure the OTP format matches the parser (typically 4-8 digit codes)
- The app only monitors emails received in the last 5 minutes

**Notifications not appearing:**
- Check macOS notification permissions in System Preferences
- Ensure otpbar has permission to send notifications

## Roadmap

Potential features for future releases:
- [ ] Support for multiple email providers
- [ ] Custom polling interval settings
- [ ] Configurable notification preferences
- [ ] Code expiration indicators

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details

## Acknowledgments

- Built with [Electron](https://www.electronjs.org/)
- Uses [menubar](https://github.com/max-mapper/embedded-tool-menubar)
- Powered by [Google APIs](https://developers.google.com/)