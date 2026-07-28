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
