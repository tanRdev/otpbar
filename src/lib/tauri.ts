import { invoke } from "@tauri-apps/api/core";
import { CodeEntry, AuthResult } from "../types/tauri";

export const tauriApi = {
  getCodes: async (): Promise<CodeEntry[]> => {
    return invoke("get_codes");
  },

  getAuthStatus: async (): Promise<boolean> => {
    return invoke("get_auth_status");
  },

  startAuth: async (): Promise<AuthResult> => {
    return invoke("start_auth");
  },

  copyCode: async (code: string): Promise<boolean> => {
    return invoke("copy_code", { code });
  },

  logout: async (): Promise<boolean> => {
    return invoke("logout");
  },

  quitApp: async (): Promise<void> => {
    return invoke("quit_app");
  },

  hideWindow: async (): Promise<void> => {
    return invoke("hide_window");
  }
};
