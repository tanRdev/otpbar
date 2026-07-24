import { pathToFileURL } from "node:url";

export const expectedNodeVersion = "24.18.0";
export const expectedNpmVersion = "11.16.0";

export function validateToolchain({
  nodeVersion = process.versions.node,
  npmUserAgent = process.env.npm_config_user_agent,
} = {}) {
  const errors = [];
  const npmVersion = npmUserAgent?.match(/(?:^|\s)npm\/([^\s]+)/)?.[1];

  if (nodeVersion !== expectedNodeVersion) {
    errors.push(
      `Node.js ${expectedNodeVersion} is required; found ${nodeVersion}.`,
    );
  }

  if (npmVersion !== expectedNpmVersion) {
    errors.push(
      `npm ${expectedNpmVersion} is required; found ${npmVersion ?? "unknown"}.`,
    );
  }

  return errors;
}

export function assertToolchain(options) {
  const errors = validateToolchain(options);

  if (errors.length > 0) {
    for (const error of errors) {
      console.error(error);
    }
    process.exitCode = 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  assertToolchain();
}
