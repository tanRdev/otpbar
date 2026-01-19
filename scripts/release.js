#!/usr/bin/env node

import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { join } from 'path';

function runCommand(cmd, description) {
  console.log(`\n${description}...`);
  try {
    execSync(cmd, { stdio: 'inherit' });
    console.log(`✅ ${description} complete`);
  } catch (error) {
    console.error(`❌ ${description} failed`);
    process.exit(1);
  }
}

function getVersion() {
  const pkg = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
  return pkg.version;
}

function checkGitHubCLI() {
  try {
    execSync('gh auth status', { stdio: 'pipe' });
    console.log('✅ GitHub CLI authenticated');
    return true;
  } catch (error) {
    console.error('❌ GitHub CLI not authenticated. Run: gh auth login');
    process.exit(1);
  }
}

function checkBuildArtifacts(version) {
  const fs = require('fs');
  const distPath = join(__dirname, '../dist');

  if (!fs.existsSync(distPath)) {
    console.error('❌ dist/ directory not found. Run: npm run dist');
    process.exit(1);
  }

  const files = fs.readdirSync(distPath);
  const expectedFiles = [`OTPBar-${version}-arm64.dmg`, `OTPBar-${version}-x64.dmg`];
  const hasExpectedFiles = expectedFiles.every(file => files.includes(file));

  if (!hasExpectedFiles) {
    console.error('❌ Build artifacts not found. Expected:', expectedFiles.join(', '));
    console.error('Available files:', files.filter(f => f.endsWith('.dmg')).join(', '));
    process.exit(1);
  }

  console.log('✅ Build artifacts found');
  return expectedFiles.map(f => join(distPath, f));
}

async function createRelease(version) {
  const tag = `v${version}`;
  const artifacts = checkBuildArtifacts(version);

  console.log(`\n🚀 Creating release ${tag}...`);

  // Check if tag exists locally
  try {
    execSync(`git tag -l ${tag}`, { stdio: 'pipe' });
    console.log(`⚠️  Tag ${tag} already exists locally. Deleting...`);
    execSync(`git tag -d ${tag}`, { stdio: 'inherit' });
  } catch (error) {
    // Tag doesn't exist, which is fine
  }

  // Check if tag exists remotely
  try {
    execSync(`git ls-remote --tags origin ${tag}`, { stdio: 'pipe' });
    console.log(`⚠️  Tag ${tag} already exists remotely. Deleting...`);
    execSync(`git push origin --delete ${tag}`, { stdio: 'inherit' });
  } catch (error) {
    // Tag doesn't exist remotely, which is fine
  }

  // Create and push tag
  runCommand(`git tag -a ${tag} -m "Release ${tag}"`, `Creating tag ${tag}`);
  runCommand(`git push origin ${tag}`, `Pushing tag ${tag}`);

  // Create release
  console.log(`\n📦 Creating GitHub release...`);

  const releaseArgs = [
    'gh',
    'release',
    'create',
    tag,
    '--title', `OTPBar v${version}`,
    '--generate-notes',
    ...artifacts
  ];

  try {
    execSync(releaseArgs.join(' '), { stdio: 'inherit' });
    console.log(`\n✅ Release ${tag} created successfully!`);
    console.log(`🔗 View release: https://github.com/tanRdev/otpbar/releases/tag/${tag}`);
  } catch (error) {
    console.error(`\n❌ Failed to create release`);
    console.error(`You may need to create it manually:`);
    console.error(`  gh release create ${tag} --title "otpbar v${version}" --generate-notes ${artifacts.join(' ')}`);
    process.exit(1);
  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: npm run release <version>');
    console.error('Example: npm run release 1.0.0');
    process.exit(1);
  }

  const version = args[0];

  console.log(`🎯 otpbar Release Script v${version}`);
  console.log('=' .repeat(50));

  checkGitHubCLI();

  const versionPattern = /^\d+\.\d+\.\d+$/;
  if (!versionPattern.test(version)) {
    console.error(`❌ Invalid version format: ${version}`);
    console.error('Version must be in format: X.Y.Z (e.g., 1.0.0)');
    process.exit(1);
  }

  // Build
  runCommand('npm run build', 'Building TypeScript');
  runCommand('npm run dist', 'Creating distribution packages');

  // Create release
  await createRelease(version);

  console.log('\n🎉 All done! Release created successfully.');
}

main();