# Contributing to OTPBar

Thank you for your interest in contributing to OTPBar! This document provides guidelines for contributing to the project.

## Setting Up Development Environment

1. **Install Prerequisites**
   - **Rust 1.94.0**: installed automatically from `rust-toolchain.toml`
   - **Node.js 24.18.0** and **npm 11.16.0**: pinned in `.nvmrc` and `package.json`
   - **Go 1.26.5**: pinned in `.go-version`
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

4. **Run the quality gates**

   ```bash
   npm run verify
   ```

   The workflow validator is actionlint `v1.7.12`, resolved through Go's
   versioned module download and checksum verification. The pinned Go version
   is required when running the complete gate locally.

5. **Set up environment variables**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` and add the public Google OAuth client ID (see README for setup
   instructions). OTPBar is a Desktop public client and does not use a client
   secret.

6. **Install the pinned Rust security auditor**
   ```bash
   cargo install cargo-audit --version 0.22.2 --locked
   ```
   Verification rejects missing or differently versioned `cargo-audit`
   installations. Its two documented RustSec exceptions are limited to a
   Windows-only notification dependency and fail closed if that dependency
   chain changes.

## Build and Test Commands

### Development

```bash
npm run dev          # Start dev server (Vite + Tauri)
npm run build        # Build frontend only
npm run tauri dev    # Run Tauri in dev mode
npm run verify       # Run every gate and build the unsigned DMG
```

### Available Scripts

- `npm run dev` - Development mode with hot reload (frontend)
- `npm run build` - Compile TypeScript and bundle frontend
- `npm run verify:code` - Run format, lint, typecheck, tests, builds, Rust/npm security audits, and workflow validation
- `npm run verify:bundle` - Build the unsigned production DMG
- `npm run verify` - Run code gates and the production bundle gate
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
│   │   ├── main.rs          # App entry and desktop runtime wiring
│   │   ├── authorization/   # OAuth lifecycle, provider, callback, and credentials
│   │   │   ├── core.rs      # Pure Authorization state machine
│   │   │   ├── google.rs    # Google public-client transport
│   │   │   ├── loopback.rs  # Ephemeral loopback callback listener
│   │   │   ├── credentials.rs # Versioned credential persistence
│   │   │   └── runtime.rs   # Single cancellable Authorization owner
│   │   ├── intake/
│   │   │   └── scheduler.rs # Single-owner mailbox intake scheduler
│   │   ├── mailbox/
│   │   │   └── gmail.rs     # Bounded Gmail read-only transport
│   │   ├── otp.rs           # OTP extraction logic
│   │   └── types.rs         # Shared data structures
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
- Use Prettier's default double quotes for strings
- Add trailing commas in multi-line objects/arrays
- Use Prettier's default 80-character print width

### Naming Conventions

- **Rust files**: `snake_case.rs` (e.g., `scheduler.rs`)
- **TS/React files**: `PascalCase.tsx` (e.g., `CodeCard.tsx`)
- **Variables/functions**: `camelCase` (e.g., `getAuthUrl`)
- **Rust structs**: `PascalCase` (e.g., `AuthorizationHandle`)
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
- **Authorization Core**: `authorization/core.rs` owns the pure state
  transitions; provider, browser, storage, and callback I/O stay behind
  adapters.
- **OAuth Flow**: Each attempt binds an IP-literal loopback listener on an
  ephemeral port before opening the browser. The flow uses PKCE and a public
  Desktop client ID, with no embedded client secret.
- **Credential Ownership**: `authorization/runtime.rs` is the single
  cancellable owner. It restores, refreshes, and atomically persists the
  versioned credential bundle before publishing `Connected` or lending a
  redacted request credential. Refresh tokens never cross that boundary.
- **Mailbox Transport**: `mailbox/gmail.rs` implements bounded, read-only Gmail
  requests and returns typed, secret-free failures to intake.
- **Intake Scheduling**: `intake/scheduler.rs` is the single scheduler owner. It
  starts only when encrypted-state migration and Authorization are ready,
  coalesces wakeups, cancels promptly on disconnect, applies jitter to healthy
  checks, and uses bounded exponential or provider-directed retry delays.
- **Runtime State**: Long-lived owners publish safe snapshots over watch/event
  channels; command channels serialize mutations instead of placing the whole
  application behind a shared `AppState` mutex.

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
