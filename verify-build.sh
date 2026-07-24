#!/usr/bin/env bash

set -euo pipefail

# actionlint is resolved from its immutable Go module version in package.json.
# Go verifies the downloaded module with go.sum/checksum-database metadata.
npm run verify
