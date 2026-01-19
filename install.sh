#!/bin/bash

set -e

echo "Installing otpbar..."

if [[ "$OSTYPE" != "darwin"* ]]; then
  echo "Error: This installer only supports macOS"
  exit 1
fi

LATEST_RELEASE=$(curl -s https://api.github.com/repos/tanRdev/otpbar/releases/latest | grep "browser_download_url.*dmg" | grep -o '"[^"]*"' | head -n 1 | cut -d '"' -f 2)

if [ -z "$LATEST_RELEASE" ]; then
  echo "Error: Could not find latest release"
  exit 1
fi

DMG_FILE=$(basename "$LATEST_RELEASE")

echo "Downloading $DMG_FILE..."
curl -L -o "/tmp/$DMG_FILE" "$LATEST_RELEASE"

echo "Installing..."
MOUNT_POINT=$(hdiutil attach "/tmp/$DMG_FILE" -readonly -nobrowse -mountpoint required -plist 2>/dev/null | grep -A1 "<key>mount-point</key>" | tail -n1 | sed 's/.*<string>\(.*\)<\/string>.*/\1/')

if [ ! -d "$MOUNT_POINT" ]; then
  echo "Error: Could not mount DMG"
  exit 1
fi

APP_NAME=$(ls "$MOUNT_POINT"/*.app | head -n1 | xargs basename)

cp -R "$MOUNT_POINT/$APP_NAME" /Applications/

hdiutil detach "$MOUNT_POINT" -quiet || true
rm "/tmp/$DMG_FILE"

echo "Installation complete! otpbar is now in /Applications"