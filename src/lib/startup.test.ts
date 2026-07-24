import { describe, expect, it } from "vitest";

import { initialStartupState, startupReducer } from "./startup";

describe("startupReducer", () => {
  it("finishes a successful startup", () => {
    expect(startupReducer(initialStartupState, { type: "finished" })).toEqual({
      status: "ready",
    });
  });

  it("keeps the latest startup failure after initialization finishes", () => {
    const degraded = startupReducer(initialStartupState, {
      type: "failed",
      error: "Failed to load OTP codes.",
    });

    expect(startupReducer(degraded, { type: "finished" })).toEqual({
      status: "degraded",
      error: "Failed to load OTP codes.",
    });
  });

  it("resets a degraded startup before retrying", () => {
    const degraded = startupReducer(initialStartupState, {
      type: "failed",
      error: "Unable to verify authentication.",
    });

    expect(startupReducer(degraded, { type: "reset" })).toEqual(
      initialStartupState,
    );
  });
});
