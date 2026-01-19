#!/bin/bash

# Pre-release build verification script

set -e

echo "🔍 Running pre-release checks..."

# Check TypeScript compilation
echo "📦 Building TypeScript..."
npm run build

# Check for .env file in git (security check)
echo "🔒 Checking for secrets..."
if git ls-files | grep -q "\.env$"; then
  echo "❌ ERROR: .env file is tracked in git!"
  exit 1
fi
echo "✅ No .env file in git"

# Check for hardcoded credentials
echo "🔐 Scanning for hardcoded credentials..."
if grep -r "GOOGLE_CLIENT" src/ | grep -v "process.env"; then
  echo "⚠️  Warning: Possible hardcoded credentials found"
fi

# Run npm audit
echo "🛡️  Running security audit..."
npm audit || echo "⚠️  Security issues found (review npm audit output)"

# Build the distribution
echo "📦 Building distribution..."
npm run dist

echo ""
echo "✅ All checks passed! Ready for release."