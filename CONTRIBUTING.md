# Contributing to OTPBar

Thank you for your interest in contributing to OTPBar! This document provides guidelines for contributing to the project.

## Setting Up Development Environment

1. **Install Prerequisites**
   - **Rust**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
   - **Node.js** (v18+): `brew install node`
   - **Xcode Command Line Tools**: `xcode-select --install`

2. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/otpbar.git
   cd otpbar
   ```

3. **Install dependencies**
   ```bash
   npm install
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add your Google OAuth credentials (see README for setup instructions)

## Build and Test Commands

### Development

```bash
npm run dev          # Start dev server (Vite + Tauri)
npm run build        # Build frontend only
npm run tauri dev    # Run Tauri in dev mode
npm run tauri build  # Build distributable DMG
```

### Available Scripts

- `npm run dev` - Development mode with hot reload (frontend)
- `npm run build` - Compile TypeScript and bundle frontend
- `npm run tauri dev` - Full dev mode (Rust + frontend)
- `npm run tauri build` - Create release builds

## Project Structure

```
otpbar/
├── src/                    # React frontend
│   ├── components/         # UI components (Auth, CodeCard, CodeList)
│   ├── lib/               # Utilities and Tauri API wrapper
│   ├── types/             # TypeScript type definitions
│   └── App.tsx            # Main React component
├── src-tauri/             # Rust backend
│   ├── src/
│   │   ├── main.rs        # App entry, tray setup, polling loop
│   │   ├── gmail.rs       # Gmail API client, OAuth flow
│   │   ├── otp.rs         # OTP extraction logic
│   │   ├── keychain.rs    # Keychain storage
│   │   ├── oauth_server.rs # Local OAuth callback server
│   │   └── types.rs       # Shared data structures
│   ├── Cargo.toml         # Rust dependencies
│   └── tauri.conf.json    # Tauri configuration
└── package.json           # Node.js dependencies
```

## Code Style Guidelines

### Rust

- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Prefer idiomatic Rust patterns
- Add doc comments for public APIs

### TypeScript

- Use TypeScript for all new code
- Enable strict mode in `tsconfig.json`
- Add type annotations for function parameters and return types
- Avoid `any` types unless absolutely necessary

### Formatting

- Use 2 spaces for indentation
- Use single quotes for strings
- Add trailing commas in multi-line objects/arrays
- Maximum line length: 100 characters

### Naming Conventions

- **Rust files**: `snake_case.rs` (e.g., `gmail.rs`)
- **TS/React files**: `PascalCase.tsx` (e.g., `CodeCard.tsx`)
- **Variables/functions**: `camelCase` (e.g., `getAuthUrl`)
- **Rust structs**: `PascalCase` (e.g., `GmailClient`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `POLL_INTERVAL_MS`)

## Pull Request Process

1. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```

2. **Make your changes**
   - Follow the code style guidelines
   - Test your changes thoroughly
   - Update documentation if needed

3. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add feature description"
   ```

   Use conventional commit messages:
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `style:` - Code style changes (formatting)
   - `refactor:` - Code refactoring
   - `test:` - Adding tests
   - `chore:` - Maintenance tasks

4. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a pull request** to `tanRdev/otpbar:main`

## Testing

### Manual Testing Checklist

- [ ] App builds without errors (`npm run build`)
- [ ] App starts without errors (`npm run dev`)
- [ ] OAuth authentication works
- [ ] OTP codes are detected from Gmail
- [ ] Codes are copied to clipboard
- [ ] Notifications appear correctly
- [ ] Menubar UI displays correctly
- [ ] Sign out functionality works

### Rust-Specific Testing

```bash
cargo clippy           # Check for common mistakes
cargo test             # Run unit tests (if any)
```

### TypeScript-Specific Testing

```bash
tsc --noEmit           # Type check without emitting files
```

## Reporting Issues

When reporting bugs, please include:

1. **OS and version** (e.g., macOS 14.0)
2. **Rust version** (`rustc --version`)
3. **Node.js version** (`node --version`)
4. **Steps to reproduce**
5. **Expected behavior**
6. **Actual behavior**
7. **Error messages (if any)**

Use the [GitHub Issues](https://github.com/tanRdev/otpbar/issues) page.

## Architecture Notes

- **Tauri Commands**: Defined in `main.rs` and exposed to frontend via `invoke()`
- **State Management**: Uses `AppState` with async mutexes for shared state
- **Polling**: Gmail is polled every 8 seconds for unread messages
- **Keychain**: OAuth tokens stored via `keyring` crate
- **OAuth Flow**: Local HTTP server on port 8234 handles callback

## Feature Requests

For feature requests:

1. Check if the feature has already been requested
2. Create a new issue with the "enhancement" label
3. Describe the use case and proposed solution
4. Discuss implementation approach with maintainers

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues and discussions
- Read the documentation in the README

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Welcome new contributors
- Give credit where due

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
