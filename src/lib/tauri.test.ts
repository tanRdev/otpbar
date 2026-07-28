import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { tauriApi } from "./tauri";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const invokeMock = vi.mocked(invoke);

describe.each([
  ["copyCode", "copy_code"],
  ["copyCodeWithExpiry", "copy_code_with_expiry"],
] as const)("%s", (method, command) => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("unwraps a successful command envelope", async () => {
    invokeMock.mockResolvedValue({ status: "success", data: true });

    await expect(tauriApi[method]("123456")).resolves.toBe(true);
    expect(invokeMock).toHaveBeenCalledWith(command, { code: "123456" });
  });

  it("rejects with the safe typed command error", async () => {
    const error = {
      code: "clipboard_unavailable",
      message: "The clipboard is temporarily unavailable.",
      retryable: true,
    } as const;
    invokeMock.mockResolvedValue({ status: "error", error });

    await expect(tauriApi[method]("654321")).rejects.toEqual(error);
  });
});

describe.each([
  ["getMonitoringHealth", "get_monitoring_health"],
  ["startMonitoring", "start_monitoring"],
  ["stopMonitoring", "stop_monitoring"],
  ["checkMonitoringNow", "check_monitoring_now"],
] as const)("%s", (method, command) => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("invokes only its declared Monitoring command", async () => {
    const health = {
      status: "stopped",
      last_success: null,
      next_action: null,
    } as const;
    invokeMock.mockResolvedValue(health);

    await expect(tauriApi[method]()).resolves.toEqual(health);
    expect(invokeMock).toHaveBeenCalledWith(command);
  });
});

describe.each([
  ["getAuthorizationStatus", "get_authorization_status"],
  ["beginAuthorization", "begin_authorization"],
  ["cancelAuthorization", "cancel_authorization"],
  ["disconnectAuthorization", "disconnect_authorization"],
] as const)("%s", (method, command) => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("invokes only its declared Authorization command", async () => {
    const status = { status: "disconnected" } as const;
    invokeMock.mockResolvedValue(status);

    await expect(tauriApi[method]()).resolves.toEqual(status);
    expect(invokeMock).toHaveBeenCalledWith(command);
  });
});
