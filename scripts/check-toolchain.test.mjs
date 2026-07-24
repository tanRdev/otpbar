import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  expectedNodeVersion,
  expectedNpmVersion,
  validateToolchain,
} from "./check-toolchain.mjs";

const matchingNpmUserAgent = `npm/${expectedNpmVersion} node/v${expectedNodeVersion} darwin arm64`;

describe("toolchain preflight", () => {
  it("accepts the pinned Node.js and npm versions", () => {
    expect(
      validateToolchain({
        nodeVersion: expectedNodeVersion,
        npmUserAgent: matchingNpmUserAgent,
      }),
    ).toEqual([]);
  });

  it("rejects mismatched Node.js and npm versions", () => {
    expect(
      validateToolchain({
        nodeVersion: "24.17.0",
        npmUserAgent: "npm/11.15.0 node/v24.17.0 darwin arm64",
      }),
    ).toEqual([
      "Node.js 24.18.0 is required; found 24.17.0.",
      "npm 11.16.0 is required; found 11.15.0.",
    ]);
  });

  it("exits nonzero when npm is not the pinned version", () => {
    const scriptPath = resolve(process.cwd(), "scripts/check-toolchain.mjs");
    const result = spawnSync(process.execPath, [scriptPath], {
      encoding: "utf8",
      env: {
        ...process.env,
        npm_config_user_agent: `npm/0.0.0 node/v${expectedNodeVersion}`,
      },
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `npm ${expectedNpmVersion} is required; found 0.0.0.`,
    );
  });
});
