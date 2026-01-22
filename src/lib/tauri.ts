import { invoke } from "@tauri-apps/api/core";
import { CodeEntry, AuthResult, PrivacyData, ClipboardConfig, PrivacyPreferences } from "../types/tauri";

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
  },

  getPrivacyData: async (): Promise<PrivacyData> => {
    return invoke("get_privacy_data");
  },

  clearHistory: async (): Promise<void> => {
    return invoke("clear_history");
  },

  copyCodeWithExpiry: async (code: string): Promise<boolean> => {
    return invoke("copy_code_with_expiry", { code });
  },

  getClipboardConfig: async (): Promise<ClipboardConfig> => {
    return invoke("get_clipboard_config");
  },

  setClipboardTimeout: async (timeoutSeconds: number): Promise<void> => {
    return invoke("set_clipboard_timeout", { timeoutSeconds });
  },

  getPreferences: async (): Promise<PrivacyPreferences> => {
    return invoke("get_preferences");
  },

  setAutoCopyEnabled: async (enabled: boolean): Promise<void> => {
    return invoke("set_auto_copy_enabled", { enabled });
  },

  setProviderAutoCopy: async (provider: string, enabled: boolean): Promise<void> => {
    return invoke("set_provider_auto_copy", { provider, enabled });
  }
};
