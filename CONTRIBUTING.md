# Contributing to OTP Watcher

Thank you for your interest in contributing to OTP Watcher! This document provides guidelines for contributing to the project.

## Setting Up Development Environment

1. **Fork the repository**
   - Click "Fork" on the GitHub repository page

2. **Clone your fork**
   ```bash
   git clone https://github.com/your-username/otpbar.git
   cd otpbar
   ```

3. **Add the upstream repository**
   ```bash
   git remote add upstream https://github.com/original-owner/otpbar.git
   ```

4. **Install dependencies**
   ```bash
   npm install
   ```

5. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add your Google OAuth credentials (see README for setup instructions)

## Build and Test Commands

### Development

```bash
# Build TypeScript and run Electron
npm run dev

# Or build separately
npm run build
```

### Available Scripts

- `npm run build` - Compile TypeScript to JavaScript
- `npm start` - Build and start the application
- `npm run dev` - Development mode with auto-rebuild

## Code Style Guidelines

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

- Files: `kebab-case.ts` (e.g., `gmail-client.ts`)
- Variables/functions: `camelCase` (e.g., `getAuthUrl`)
- Classes/Interfaces: `PascalCase` (e.g., `GmailClient`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `POLL_MS`)

### Code Organization

- Keep functions focused and single-purpose
- Add comments only for complex logic
- Group related exports together
- Use ES6 imports/exports

## Pull Request Process

### Before Submitting

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

### Submitting a Pull Request

1. **Create a pull request** from your fork to the upstream repository
2. **Fill out the PR template**:
   - Describe the changes
   - List related issues (if any)
   - Add screenshots for UI changes (if applicable)
3. **Request a review** from maintainers

### PR Review Guidelines

- Address all review comments
- Keep PRs focused and small
- Ensure all tests pass
- Update documentation as needed

## Testing

### Manual Testing Checklist

- [ ] App builds without errors (`npm run build`)
- [ ] App starts without errors (`npm start`)
- [ ] OAuth authentication works
- [ ] OTP codes are detected from Gmail
- [ ] Codes are copied to clipboard
- [ ] Notifications appear correctly
- [ ] Menubar UI displays correctly
- [ ] Sign out functionality works

### Platform Testing

Test on all supported platforms when making UI or platform-specific changes:
- macOS
- Windows
- Linux

## Reporting Issues

When reporting bugs, please include:

1. **OS and version**
2. **Node.js version**
3. **App version**
4. **Steps to reproduce**
5. **Expected behavior**
6. **Actual behavior**
7. **Error messages (if any)**
8. **Screenshots (if applicable)**

Use the [GitHub Issues](https://github.com/your-username/otpbar/issues) page to report bugs or request features.

## Feature Requests

For feature requests:

1. Check if the feature has already been requested
2. Create a new issue with "enhancement" label
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
